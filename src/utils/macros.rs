#[macro_export]
macro_rules! LOGTRACE {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.trace(format!($($arg)*),Some($kvl));
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.trace(format!($($arg)*),None);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! LOGDEBUG {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.debug(format!($($arg)*),Some($kvl));
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.debug(format!($($arg)*),None);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! LOGINFO {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.info(format!($($arg)*),Some($kvl));
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.info(format!($($arg)*),None);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! LOGSUCCESS {
    (kvl: $kvl:expr,$($arg:tt)+) => {{ 
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.success(format!($($arg)*),Some($kvl));
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.success(format!($($arg)*),None);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! LOGRESULT {
    (clean: $clean:expr,kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.result(format!($($arg)*),Some($kvl),$clean);
        drop(lock);
    }};
    (clean: $clean:expr,$($arg:tt)*) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.result(format!($($arg)*),None,$clean);
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.result(format!($($arg)*),None,true);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! LOGNOTICE {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.notice(format!($($arg)*),Some($kvl));
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.notice(format!($($arg)*),None);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! LOGWARN {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.warn(format!($($arg)*),Some($kvl));
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.warn(format!($($arg)*),None);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! LOGALERT {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.alert(format!($($arg)*),Some($kvl));
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.alert(format!($($arg)*),None);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! LOGERROR {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.error(format!($($arg)*),Some($kvl));
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.error(format!($($arg)*),None);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! LOGFATAL {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.fatal(format!($($arg)*),Some($kvl));
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.fatal(format!($($arg)*),None);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! SETPROGRESS {
    ($length:expr) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.set_progress($length);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! INCLENGTHPROGRESS {
    ($length:expr) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.inc_length_progress($length);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! INCPROGRESS {
    ($length:expr) => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.inc_progress($length);
        drop(lock);
    }};
}
#[macro_export]
macro_rules! DELETEPROGRESS {
    () => {{
        let lock = crate::utils::statics::LOGGER.read().unwrap();
        lock.delete_progress();
        drop(lock);
    }};
}