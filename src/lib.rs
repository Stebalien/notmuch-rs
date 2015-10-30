#![feature(convert)]
extern crate notmuch_sys;
extern crate libc;
#[macro_use]
extern crate log;

#[macro_use(abort_on_panic)]
extern crate abort_on_panic;

use notmuch_sys::*;
use std::{mem, io, ptr, fmt};
use std::path::Path;
use std::marker::PhantomData;
use std::ffi::{OsStr, CString, CStr};
use std::ops::{Deref, DerefMut};

extern {
    // OS-level abort function, because std::intrinsics::abort is unstable.
    fn abort() -> !;
}

struct Guard<T, F, O>(Option<(T, F)>) where F: FnOnce(T) -> O;

impl<T, F, O> Guard<T, F, O>
    where F: FnOnce(T) -> O
{
    pub fn unguard(mut self) -> T {
        let (value, _) = self.0.take().unwrap();
        value
    }
    pub fn run(mut self) -> O {
        let (value, func) = self.0.take().unwrap();
        (func)(value)
    }
}

impl<T, F, O> Drop for Guard<T, F, O>
    where F: FnOnce(T) -> O
{
    fn drop(&mut self) {
        if let Some((value, func)) = self.0.take() {
            let _ = (func)(value);
        }
    }
}

fn guard<T, F, O>(value: T, func: F) -> Guard<T, F, O>
    where F: FnOnce(T) -> O
{
    Guard(Some((value, func)))
}

#[derive(Debug)]
pub enum Error {
    ReadOnlyDatabase,
    XapianException,
    FileError(io::Error),
    FileNotEmail,
    InvalidTag,
}



fn handle_error(e: notmuch_status_t) -> Result<(), Error> {
    use notmuch_sys::notmuch_status_t::*;
    use Error::*;
    match e {
        SUCCESS => Ok(()),
        DUPLICATE_MESSAGE_ID => Ok(()),
        READ_ONLY_DATABASE => Err(ReadOnlyDatabase),
        XAPIAN_EXCEPTION => Err(XapianException),
        FILE_NOT_EMAIL => Err(FileNotEmail),
        TAG_TOO_LONG => Err(InvalidTag),
        FILE_ERROR => Err(FileError(io::Error::last_os_error())),
        NULL_POINTER => panic!("BUG: we passed a null pointer"),
        UNBALANCED_FREEZE_THAW => panic!("BUG: Unbalanced freeze thaw"),
        UNBALANCED_ATOMIC => panic!("BUG: Unbalanced freeze atomic"),
        UNSUPPORTED_OPERATION => panic!("BUG: Unsupported operation"),
        UPGRADE_REQUIRED => panic!("BUG: Upgrade required"),
        PATH_ERROR => panic!("BUG: Path error. We didn't make a path absolute"),
        // Rust aborts on OOM
        // TODO: When rust gets custom allocation/oom handlers, do something else.
        OUT_OF_MEMORY => unsafe { abort() },
    }
}

/// A notmuch database handle.
pub struct Database {
    handle: *mut notmuch_database_t,
}

fn cpath<P: AsRef<Path>>(path: P) -> Result<CString, Error> {
    if let Some(path) = path.as_ref().as_os_str().to_cstring() {
        Ok(path)
    } else {
        Err(Error::FileError(io::Error::new(io::ErrorKind::NotFound, "path contained interrior nulls")))
    }
}

fn cstr<S: AsRef<str>>(s: S) -> Option<CString> {
    AsRef::<OsStr>::as_ref(s.as_ref()).to_cstring()
}

// XXX FIXME TODO: Make path absolute
impl Database {
    // TODO: Combine methods. I don't want the user to care about this stuff!
    // We really want:
    // open(...)
    // create(...)
    //
    // and some advanced open with options?
    //
    // May need to modify notmuch...
    pub fn create<P: AsRef<Path>>(path: P) -> Result<Database, Error> {
        let path = try!(cpath(path));
        unsafe {
            let mut db = ptr::null_mut();
            try!(handle_error(notmuch_database_create(path.as_ptr(), &mut db)));
            Ok(Database {
                handle: db
            })
        }
    }
    pub fn open_readonly<P: AsRef<Path>>(path: P) -> Result<Database, Error> {
        let path = try!(cpath(path));
        unsafe {
            let mut db = ptr::null_mut();
            try!(handle_error(notmuch_database_open(path.as_ptr(), notmuch_database_mode_t::READ_ONLY, &mut db)));

            Ok(Database {
                handle: db
            })
        }
    }

    pub fn open_readwrite<P>(path: P) -> Result<Database, Error>
        where P: AsRef<Path>
    {
        Database::open_readwrite_helper(path.as_ref(), None)
    }

    /// Note: This will abort if the callback panics!
    pub fn open_readwrite_with_progress<P, C>(path: P, mut progress: C) -> Result<Database, Error>
        where P: AsRef<Path>, C: FnMut(f64)
    {
        Database::open_readwrite_helper(path.as_ref(), Some(&mut progress as &mut FnMut(f64)))
    }

    fn open_readwrite_helper(path: &Path, cb: Option<&mut FnMut(f64)>) -> Result<Database, Error> {
        extern "C" fn progress(closure: *mut libc::c_void, p: f64) {
            abort_on_panic! {{
                unsafe {
                    let closure: &mut &mut FnMut(f64) = mem::transmute(closure);
                    (closure)(p);
                }
            }}
        }
        let path = try!(cpath(path));
        unsafe {
            let mut db = ptr::null_mut();
            try!(handle_error(notmuch_database_open(path.as_ptr(), notmuch_database_mode_t::READ_WRITE, &mut db)));
            let db = Database { handle: db };
            try!(handle_error(if let Some(mut cb) = cb {
                let cb: *mut libc::c_void = mem::transmute(&mut cb);
                notmuch_database_upgrade(db.handle, Some(progress), cb)
            } else {
                notmuch_database_upgrade(db.handle, None, ptr::null_mut())
            }));
            Ok(db)
        }
    }


    /// Atomically modify the datbase.
    ///
    /// Modifications made inside the callback will not be fushed to the database until this
    /// function returns or panics.
    ///
    /// **Note:** This is not a transaction; there is no way to abort.
    pub fn atomic<'a, T, F>(&'a self, f: F) -> Result<T, Error>
        where F: FnOnce(&'a Self) -> T
    {
        use notmuch_sys::notmuch_status_t::*;
        let guard = unsafe {
            // This can't fail.
            // Error conditions:
            //   1. Database needs upgrade: we upgrade on open.
            //   2. Unsupported operation: this is supported in on-disk databases.
            //   3. InvalidOperationError: no transaction can be in progress (notmuch guarantee).
            assert_eq!(notmuch_database_begin_atomic(self.handle), SUCCESS);

            guard(self.handle, |handle| {
                handle_error(notmuch_database_end_atomic(handle))
            })
        };
        let result = (f)(self);
        guard.run().and(Ok(result))
    }

    /// Add a message to the database.
    ///
    /// If the message is already present, the new filename will be added to the existing message
    /// and the existing message will be returned.
    pub fn add_message<'a, P>(&'a self, path: P) -> Result<Message<'a>, Error>
        where P: AsRef<Path>
    {
        let path = try!(cpath(path));
        unsafe {
            let mut msg = ptr::null_mut();

            try!(handle_error(notmuch_database_add_message(self.handle, path.as_ptr(), &mut msg)));
            Ok(Message {
                _marker: PhantomData,
                handle: msg
            })
        }
    }

    unsafe fn close_helper(&mut self) -> Result<(), Error> {
        // Unsafe because this invalidates self.
        handle_error(notmuch_database_destroy(self.handle))
    }

    /// Close the database and flush any unwritten modifications.
    ///
    /// The database will automatically be closed on drop but calling this method lets one detect
    /// errors.
    pub fn close(mut self) -> Result<(), Error> {
        unsafe {
            let result = self.close_helper();
            mem::forget(self);
            result
        }
    }

    /// Get all tags in the database.
    pub fn tags<'a>(&'a self) -> Result<Tags<'a>, Error> {
        unsafe {
            let handle = notmuch_database_get_all_tags(self.handle);
            if handle.is_null() {
                Err(Error::XapianException)
            } else {
                Ok(Tags {
                    _marker: PhantomData,
                    handle: handle,
                })
            }
        }
    }
}

pub struct Tags<'a> {
    // TODO: I would like to make this entire thing an unsized type (not dst).
    _marker: PhantomData<&'a notmuch_tags_t>,
    handle: *mut notmuch_tags_t,
}

impl<'a, 'b> Iterator for &'a Tags<'b> {
    type Item = &'b str;

    fn next(&mut self) -> Option<&'b str> {
        unsafe {
            loop {
                let res = notmuch_tags_get(self.handle);
                if res.is_null() {
                    return None
                } else {
                    notmuch_tags_move_to_next(self.handle);
                    match CStr::from_ptr(res).to_str() {
                        Ok(v) => return Some(v),
                        // I'd like notmuch to just guarantee this but I'm not going to:
                        //  a. Just crash.
                        //  b. Ask the user to handle this case.
                        Err(e) => warn!("Skipping non UTF-8 tag: {:?}", e),
                    }
                }
            }
        }
    }
}

impl<'a> Drop for Tags<'a> {
    fn drop(&mut self) {
        unsafe {
            notmuch_tags_destroy(self.handle)
        }
    }
}

impl<'a> Tags<'a> {
    /// Convenience method to take self by reference because `Iterator` is implemented on
    /// `&Tags`, not `Tags`.
    pub fn iter(&self) -> &Self {
        self
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        unsafe {
            let _ = self.close_helper();
        }
    }
}

pub struct Messages<'a> {
    _marker: PhantomData<&'a notmuch_messages_t>,
    handle: *mut notmuch_messages_t,
}

impl<'a, 'b> Iterator for &'a Messages<'b> {
    type Item = Message<'b>;
    fn next(&mut self) -> Option<Message<'b>> {
        unsafe {
            let msg = notmuch_messages_get(self.handle);
            if msg.is_null() {
                None
            } else {
                notmuch_messages_move_to_next(self.handle);
                Some(Message {
                    _marker: PhantomData,
                    handle: msg,
                })
            }
        }
    }
}

impl<'a> Drop for Messages<'a> {
    fn drop(&mut self) {
        unsafe {
            notmuch_messages_destroy(self.handle);
        }
    }
}

/// A message.
pub struct Message<'a> {
    // TODO: I would like to make this entire thing an unsized type (not dst).
    _marker: PhantomData<&'a notmuch_message_t>,
    handle: *mut notmuch_message_t,
}

impl<'a> Message<'a> {
    /// Add a tag to the message.
    pub fn add_tag(&self, tag: &str) -> Result<(), Error> {
        let tag = try!(cstr(tag).ok_or(Error::InvalidTag));
        unsafe {
            handle_error(notmuch_message_add_tag(self.handle, tag.as_ptr()))
        }
    }

    /// Remove a tag from the message.
    pub fn remove_tag(&self, tag: &str) -> Result<(), Error> {
        let tag = match cstr(tag) {
            Some(t) => t,
            // Could not exist in the database.
            None => return Ok(()),
        };
        unsafe {
            match handle_error(notmuch_message_remove_tag(self.handle, tag.as_ptr())) {
                Err(Error::InvalidTag) => Ok(()),
                other => other,
            }
        }
    }

    /// Remove all tags from the message.
    pub fn remove_all_tags(&self) -> Result<(), Error> {
        unsafe {
            handle_error(notmuch_message_remove_all_tags(self.handle))
        }
    }

    /// Get the message ID.
    pub fn id<'b>(&'b self) -> &'b str {
        unsafe {
            // TODO: Will this always be utf8?
            CStr::from_ptr(notmuch_message_get_message_id(self.handle)).to_str().unwrap()
        }
    }

    /// Get the message's tags.
    pub fn tags<'b>(&'b self) -> Tags<'b> {
        unsafe {
            Tags {
                _marker: PhantomData,
                handle: notmuch_message_get_tags(self.handle)
            }
        }
    }

    /// Add/remove tags according to maildir flags in the message filename(s).
    ///
    /// This function examines the filenames of 'message' for maildir flags, and adds or removes
    /// tags on 'message' as follows when these flags are present:
    ///
    /// ```norun
    /// Flag	Action if present
    /// ----	-----------------
    /// 'D'	Adds the "draft" tag to the message
    /// 'F'	Adds the "flagged" tag to the message
    /// 'P'	Adds the "passed" tag to the message
    /// 'R'	Adds the "replied" tag to the message
    /// 'S'	Removes the "unread" tag from the message
    /// ```
    ///
    /// For each flag that is not present, the opposite action (add/remove)
    /// is performed for the corresponding tags.
    ///
    /// Flags are identified as trailing components of the filename after a
    /// sequence of ":2,".
    ///
    /// If there are multiple filenames associated with this message, the
    /// flag is considered present if it appears in one or more
    /// filenames. (That is, the flags from the multiple filenames are
    /// combined with the logical OR operator.)
    ///
    /// A client can ensure that notmuch database tags remain synchronized
    /// with maildir flags by calling this function after each call to
    /// `Database::add_message`. See also `Message::tags_to_maildir_flags` for synchronizing tag
    /// changes back to maildir flags.
    pub fn maildir_flags_to_tags(&self) -> Result<(), Error> {
        unsafe {
            handle_error(notmuch_message_maildir_flags_to_tags(self.handle))
        }
    }

    /// Rename message filename(s) to encode tags as maildir flags.
    ///
    /// Specifically, for each filename corresponding to this message:
    ///
    /// If the filename is not in a maildir directory, do nothing.  (A
    /// maildir directory is determined as a directory named "new" or
    /// "cur".) Similarly, if the filename has invalid maildir info,
    /// (repeated or outof-ASCII-order flag characters after ":2,"), then
    /// do nothing.
    ///
    /// If the filename is in a maildir directory, rename the file so that
    /// its filename ends with the sequence ":2," followed by zero or more
    /// of the following single-character flags (in ASCII order):
    ///
    ///   'D' iff the message has the "draft" tag
    ///   'F' iff the message has the "flagged" tag
    ///   'P' iff the message has the "passed" tag
    ///   'R' iff the message has the "replied" tag
    ///   'S' iff the message does not have the "unread" tag
    ///
    /// Any existing flags unmentioned in the list above will be preserved
    /// in the renaming.
    ///
    /// Also, if this filename is in a directory named "new", rename it to
    /// be within the neighboring directory named "cur".
    ///
    /// A client can ensure that maildir filename flags remain synchronized
    /// with notmuch database tags by calling this function after changing
    /// tags, (after calls to `Message::add_tag`,
    /// `Message::remove_tag`, or `Message::atomic`). See also `Message::maildir_flags_to_tags` for
    /// synchronizing maildir flag changes back to tags.
    pub fn tags_to_maildir_flags(&self) -> Result<(), Error> {
        unsafe {
            handle_error(notmuch_message_tags_to_maildir_flags(self.handle))
        }
    }

    /// Message would have been excluded from the search query results because it contains excluded
    /// tags but was included because `Query::omit_excluded` was set to false.
    pub fn excluded(&self) -> bool {
        unsafe {
            notmuch_message_get_flag(self.handle,
                                     notmuch_message_flag_t::EXCLUDED)
        }
    }

    /// Get a message header.
    ///
    /// Returns `Ok("")` if the header is empty or not present.
    pub fn header<'b>(&'b self, header: &str) -> Result<&'b str, Error> {
        let header = match cstr(header) {
            Some(v) => v,
            // Header could not be defined. Return "".
            None => return Ok(""),
        };
        unsafe {
            let value = notmuch_message_get_header(self.handle, header.as_ptr());
            if value.is_null() {
                Err(Error::XapianException)
            } else {
                // TODO: Will this always be utf8?
                Ok(CStr::from_ptr(value).to_str().unwrap())
            }
        }
    }

    /// Get a filename for the message.
    ///
    /// Messages can have multiple filenames. This returns one at random.
    ///
    /// Returns None for ghost messages. Ghost messages are messages that we know about because
    /// some other message references it but we don't have.
    pub fn filename<'b>(&'b self) -> Option<&'b Path> {
        unsafe {
            let ptr = notmuch_message_get_filename(self.handle);
            if ptr.is_null() {
                None
            } else {
                // FIXME: Is this safe?
                Some(mem::transmute(CStr::from_ptr(ptr).to_bytes()))
            }
        }
    }

    /// Atomically modify the message.
    ///
    /// Modifications to this message made inside callback will not be visible until the function
    /// returns *or panics*.
    ///
    /// **Note:** There is no way to *cancel* modifications. Panicing will also commit
    /// modifications as-is.
    pub fn atomic<'b, T, F>(&'b self, f: F) -> Result<T, Error>
        where F: FnOnce(&'b Self) -> T
    {
        unsafe {
            try!(handle_error(notmuch_message_freeze(self.handle)));
            let guard = guard(self.handle, |handle| {
                handle_error(notmuch_message_thaw(handle))
            });
            let result = (f)(self);
            guard.run().and(Ok(result))
        }
    }

    /// Get the message's thread ID.
    pub fn thread_id<'b>(&'b self) -> &'b str {
        unsafe {
            CStr::from_ptr(notmuch_message_get_thread_id(self.handle)).to_str().unwrap()
        }
    }

    /// Get all filenames associated with this message.
    pub fn filenames<'b>(&'b self) -> Filenames<'b> {
        Filenames {
            _marker: PhantomData,
            handle: unsafe { notmuch_message_get_filenames(self.handle) },
        }
    }
}

#[repr(C)]
pub struct ThreadMessage<'a>(Message<'a>);

impl<'a> ThreadMessage<'a> {
    /// Message matches query through which it was reached.
    pub fn matches_query(&self) -> bool {
        unsafe {
            notmuch_message_get_flag(self.0.handle,
                                     notmuch_message_flag_t::MATCH)
        }
    }

    /// Get replies to this message.
    pub fn replies<'b>(&'b self) -> ThreadMessages<'b> {
        unsafe {
            ThreadMessages(
                Messages {
                    _marker: PhantomData,
                    handle: notmuch_message_get_replies(self.0.handle)
                }
            )
        }
    }

    /// Atomically modify the message.
    ///
    /// Modifications to this message made inside callback will not be visible until the function
    /// returns *or panics*.
    ///
    /// **Note:** There is no way to *cancel* modifications. Panicing will also commit
    /// modifications as-is.
    pub fn atomic<'b, T, F>(&'b self, f: F) -> Result<T, Error>
        where F: FnOnce(&'b Self) -> T,
    {
        (**self).atomic(|m: &Message<'a>|f(unsafe { mem::transmute(m) }))
    }
}

pub struct ThreadMessages<'a>(Messages<'a>);

impl<'a, 'b> Iterator for &'a ThreadMessages<'b> {
    type Item = ThreadMessage<'a>;

    fn next(&mut self) -> Option<ThreadMessage<'a>> {
        (&self.0).next().map(ThreadMessage)
    }
}

impl<'a> Deref for ThreadMessage<'a> {
    type Target = Message<'a>;

    fn deref(&self) -> &Message<'a> {
        &self.0
    }
}

impl<'a> DerefMut for ThreadMessage<'a> {
    fn deref_mut(&mut self) -> &mut Message<'a> {
        &mut self.0
    }
}

pub struct Thread<'a> {
    _marker: PhantomData<&'a notmuch_thread_t>,
    handle: *mut notmuch_thread_t,
}

impl<'a> Thread<'a> {
    // TODO: Better API?
    pub fn authors<'b>(&'b self) -> &'b str {
        unsafe {
            CStr::from_ptr(notmuch_thread_get_authors(self.handle))
                .to_str()
                .unwrap()
        }
    }
}

pub struct Filenames<'a> {
    _marker: PhantomData<&'a notmuch_filenames_t>,
    handle: *mut notmuch_filenames_t
}

impl<'a> Drop for Filenames<'a> {
    fn drop(&mut self) {
        unsafe {
            notmuch_filenames_destroy(self.handle);
        }
    }
}

impl<'a, 'b> Iterator for &'a Filenames<'b> {
    type Item = &'a Path;
    fn next(&mut self) -> Option<&'a Path>{
        unsafe {
            let filename = notmuch_filenames_get(self.handle);
            if filename.is_null() {
                None
            } else {
                notmuch_filenames_move_to_next(self.handle);
                Some(mem::transmute(CStr::from_ptr(filename).to_bytes()))
            }
        }
    }
}

impl<'a> Filenames<'a> {
    /// Convenience method to take self by reference because `Iterator` is implemented on
    /// `&Filenames`, not `Filenames`.
    pub fn iter(&self) -> &Self {
        self
    }
}

impl<'a> fmt::Debug for Message<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Message").field(&self.id()).finish()
    }
}

impl<'a, 'b> PartialEq<Message<'a>> for Message<'b> {
    fn eq(&self, other: &Message) -> bool {
        unsafe {
            // Don't bother checking for utf8.
            // TODO: Remove this later and don't ever check for utf8
            CStr::from_ptr(notmuch_message_get_message_id(self.handle))
                ==
            CStr::from_ptr(notmuch_message_get_message_id(other.handle))
        }
    }
}

impl<'a> Eq for Message<'a> {}

impl<'a> Drop for Message<'a> {
    fn drop(&mut self) {
        unsafe {
            notmuch_message_destroy(self.handle)
        }
    }
}

