//! Port of lib/libalpm/error.c: the error enum and alpm_strerror messages (C locale).
//! Discriminants match `alpm_errno_t` in alpm.h (ALPM_ERR_OK = 0 is not an error, so omitted).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Error {
    Memory = 1,
    System = 2,
    Badperms = 3,
    NotAFile = 4,
    NotADir = 5,
    WrongArgs = 6,
    DiskSpace = 7,
    HandleNull = 8,
    HandleNotNull = 9,
    HandleLock = 10,
    DbOpen = 11,
    DbCreate = 12,
    DbNull = 13,
    DbNotNull = 14,
    DbNotFound = 15,
    DbInvalid = 16,
    DbInvalidSig = 17,
    DbVersion = 18,
    DbWrite = 19,
    DbRemove = 20,
    ServerBadUrl = 21,
    ServerNone = 22,
    TransNotNull = 23,
    TransNull = 24,
    TransDupTarget = 25,
    TransDupFilename = 26,
    TransNotInitialized = 27,
    TransNotPrepared = 28,
    TransAbort = 29,
    TransType = 30,
    TransNotLocked = 31,
    TransHookFailed = 32,
    PkgNotFound = 33,
    PkgIgnored = 34,
    PkgInvalid = 35,
    PkgInvalidChecksum = 36,
    PkgInvalidSig = 37,
    PkgMissingSig = 38,
    PkgOpen = 39,
    PkgCantRemove = 40,
    PkgInvalidName = 41,
    PkgInvalidArch = 42,
    SigMissing = 43,
    SigInvalid = 44,
    UnsatisfiedDeps = 45,
    ConflictingDeps = 46,
    FileConflicts = 47,
    RetrievePrepare = 48,
    Retrieve = 49,
    InvalidRegex = 50,
    Libarchive = 51,
    Libcurl = 52,
    ExternalDownload = 53,
    Gpgme = 54,
    MissingCapabilitySignatures = 55,
}

impl Error {
    /// alpm_strerror
    pub fn strerror(self) -> &'static str {
        match self {
            Error::Memory => "out of memory!",
            Error::System => "unexpected system error",
            Error::Badperms => "permission denied",
            Error::NotAFile => "could not find or read file",
            Error::NotADir => "could not find or read directory",
            Error::WrongArgs => "wrong or NULL argument passed",
            Error::DiskSpace => "not enough free disk space",
            Error::HandleNull => "library not initialized",
            Error::HandleNotNull => "library already initialized",
            Error::HandleLock => "unable to lock database",
            Error::DbOpen => "could not open database",
            Error::DbCreate => "could not create database",
            Error::DbNull => "database not initialized",
            Error::DbNotNull => "database already registered",
            Error::DbNotFound => "could not find database",
            Error::DbInvalid => "invalid or corrupted database",
            Error::DbInvalidSig => "invalid or corrupted database (PGP signature)",
            Error::DbVersion => "database is incorrect version",
            Error::DbWrite => "could not update database",
            Error::DbRemove => "could not remove database entry",
            Error::ServerBadUrl => "invalid url for server",
            Error::ServerNone => "no servers configured for repository",
            Error::TransNotNull => "transaction already initialized",
            Error::TransNull => "transaction not initialized",
            Error::TransDupTarget => "duplicate target",
            Error::TransDupFilename => "duplicate filename",
            Error::TransNotInitialized => "transaction not initialized",
            Error::TransNotPrepared => "transaction not prepared",
            Error::TransAbort => "transaction aborted",
            Error::TransType => "operation not compatible with the transaction type",
            Error::TransNotLocked => "transaction commit attempt when database is not locked",
            Error::TransHookFailed => "failed to run transaction hooks",
            Error::PkgNotFound => "could not find or read package",
            Error::PkgIgnored => "operation cancelled due to ignorepkg",
            Error::PkgInvalid => "invalid or corrupted package",
            Error::PkgInvalidChecksum => "invalid or corrupted package (checksum)",
            Error::PkgInvalidSig => "invalid or corrupted package (PGP signature)",
            Error::PkgMissingSig => "package missing required signature",
            Error::PkgOpen => "cannot open package file",
            Error::PkgCantRemove => "cannot remove all files for package",
            Error::PkgInvalidName => "package filename is not valid",
            Error::PkgInvalidArch => "package architecture is not valid",
            Error::SigMissing => "missing PGP signature",
            Error::SigInvalid => "invalid PGP signature",
            Error::UnsatisfiedDeps => "could not satisfy dependencies",
            Error::ConflictingDeps => "conflicting dependencies",
            Error::FileConflicts => "conflicting files",
            Error::RetrievePrepare => "failed to initialize download",
            Error::Retrieve => "failed to retrieve some files",
            Error::InvalidRegex => "invalid regular expression",
            Error::Libarchive => "libarchive error",
            Error::Libcurl => "download library error",
            Error::ExternalDownload => "error invoking external downloader",
            Error::Gpgme => "gpgme error",
            Error::MissingCapabilitySignatures => "compiled without signature support",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.strerror())
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages() {
        assert_eq!(Error::Memory.strerror(), "out of memory!");
        assert_eq!(
            Error::TransNotInitialized.strerror(),
            "transaction not initialized"
        );
        assert_eq!(Error::MissingCapabilitySignatures as u8, 55);
    }
}
