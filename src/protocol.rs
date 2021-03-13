use serde::{Deserialize, Serialize};
use thiserror::Error;
use vfs::{VfsError, VfsFileType, VfsMetadata, VfsResult};

#[derive(Debug, Deserialize, Serialize)]
pub enum Command {
    Exists(CommandExists),
    Metadata(CommandMetadata),
    CreateFile(CommandCreateFile),
    RemoveFile(CommandRemoveFile),
    Write(CommandWrite),
    Read(CommandRead),
    CreateDir(CommandCreateDir),
    ReadDir(CommandReadDir),
    RemoveDir(CommandRemoveDir),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandExists {
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandMetadata {
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandCreateFile {
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandRemoveFile {
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandWrite {
    pub path: String,
    pub pos: u64,
    pub len: u64,
    /// Base64 encoded data
    pub data: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandRead {
    pub path: String,
    pub pos: u64,
    pub len: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandCreateDir {
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandReadDir {
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandRemoveDir {
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CommandResponse {
    Exists(Result<bool, CommandResponseError>),
    Metadata(Result<CmdMetadata, CommandResponseError>),
    CreateFile(CommandResponseCreateFile),
    RemoveFile(Result<(), CommandResponseError>),
    Write(Result<usize, CommandResponseError>),
    Read(Result<(usize, String), CommandResponseError>),
    CreateDir(CommandResponseCreateDir),
    ReadDir(CommandResponseReadDir),
    RemoveDir(Result<(), CommandResponseError>),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CommandResponseCreateFile {
    Success,
    Failed,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CommandResponseCreateDir {
    Success,
    Failed,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandResponseReadDir {
    pub result: Result<Vec<String>, String>,
}

#[derive(Error, Debug, Deserialize, Serialize)]
pub enum CommandResponseError {
    /// A generic IO error
    #[error("IO error: {0}")]
    IoError(String),

    /// The file or directory at the given path could not be found
    #[error("The file or directory `{path}` could not be found")]
    FileNotFound {
        /// The path of the file not found
        path: String,
    },

    /// The given path is invalid, e.g. because contains '.' or '..'
    #[error("The path `{path}` is invalid")]
    InvalidPath {
        /// The invalid path
        path: String,
    },

    /// Generic error variant
    #[error("FileSystem error: {message}")]
    Other {
        /// The generic error message
        message: String,
    },

    /// Generic error context, used for adding context to an error (like a path)
    #[error("{context}, cause: {cause}")]
    WithContext {
        /// The context error message
        context: String,
        /// The underlying error
        #[source]
        cause: Box<CommandResponseError>,
    },

    /// Functionality not supported by this filesystem
    #[error("Functionality not supported by this filesystem")]
    NotSupported,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CmdMetadata {
    pub file_type: CmdFileType,
    pub len: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CmdFileType {
    File,
    Directory,
}

impl From<std::io::Error> for CommandResponseError {
    fn from(error: std::io::Error) -> Self {
        CommandResponseError::IoError(format!("{}", error))
    }
}

impl From<VfsError> for CommandResponseError {
    fn from(error: VfsError) -> Self {
        match error {
            VfsError::IoError(io) => CommandResponseError::IoError(io.to_string()),
            VfsError::FileNotFound { path } => CommandResponseError::FileNotFound { path },
            VfsError::InvalidPath { path } => CommandResponseError::InvalidPath { path },
            VfsError::Other { message } => CommandResponseError::Other { message },
            VfsError::WithContext { context, cause } => CommandResponseError::WithContext {
                context,
                cause: Box::new(CommandResponseError::from(*cause)),
            },
            VfsError::NotSupported => CommandResponseError::NotSupported,
        }
    }
}

impl From<CommandResponseError> for VfsError {
    fn from(error: CommandResponseError) -> Self {
        match error {
            CommandResponseError::IoError(io) => VfsError::Other { message: io },
            CommandResponseError::FileNotFound { path } => VfsError::FileNotFound { path },
            CommandResponseError::InvalidPath { path } => VfsError::InvalidPath { path },
            CommandResponseError::Other { message } => VfsError::Other { message },
            CommandResponseError::WithContext { context, cause } => VfsError::WithContext {
                context,
                cause: Box::new(VfsError::from(*cause)),
            },
            CommandResponseError::NotSupported => VfsError::NotSupported,
        }
    }
}

impl From<VfsMetadata> for CmdMetadata {
    fn from(vfs_meta: VfsMetadata) -> Self {
        CmdMetadata {
            file_type: CmdFileType::from(vfs_meta.file_type),
            len: vfs_meta.len,
        }
    }
}

impl From<CmdMetadata> for VfsMetadata {
    fn from(cmd_meta: CmdMetadata) -> Self {
        VfsMetadata {
            file_type: VfsFileType::from(cmd_meta.file_type),
            len: cmd_meta.len,
        }
    }
}

impl From<VfsFileType> for CmdFileType {
    fn from(vfs_file_type: VfsFileType) -> Self {
        match vfs_file_type {
            VfsFileType::File => CmdFileType::File,
            VfsFileType::Directory => CmdFileType::Directory,
        }
    }
}

impl From<CmdFileType> for VfsFileType {
    fn from(cmd_file_type: CmdFileType) -> Self {
        match cmd_file_type {
            CmdFileType::File => VfsFileType::File,
            CmdFileType::Directory => VfsFileType::Directory,
        }
    }
}

pub fn meta_res_convert_vfs_cmd(
    result: VfsResult<VfsMetadata>,
) -> Result<CmdMetadata, CommandResponseError> {
    match result {
        Err(e) => Err(CommandResponseError::from(e)),
        Ok(meta) => Ok(CmdMetadata::from(meta)),
    }
}

pub fn meta_res_convert_cmd_vfs(
    result: Result<CmdMetadata, CommandResponseError>,
) -> VfsResult<VfsMetadata> {
    match result {
        Err(e) => Err(VfsError::from(e)),
        Ok(meta) => Ok(VfsMetadata::from(meta)),
    }
}

impl From<Result<Box<(dyn std::io::Write + 'static)>, VfsError>> for CommandResponseCreateFile {
    fn from(result: Result<Box<(dyn std::io::Write + 'static)>, VfsError>) -> Self {
        match result {
            Ok(_) => CommandResponseCreateFile::Success,
            Err(_) => CommandResponseCreateFile::Failed,
        }
    }
}

impl From<Result<(), VfsError>> for CommandResponseCreateDir {
    fn from(result: Result<(), VfsError>) -> Self {
        match result {
            Ok(_) => CommandResponseCreateDir::Success,
            Err(_) => CommandResponseCreateDir::Failed,
        }
    }
}

impl From<VfsResult<Box<dyn Iterator<Item = String>>>> for CommandResponseReadDir {
    fn from(result: VfsResult<Box<dyn Iterator<Item = String>>>) -> Self {
        match result {
            Err(e) => CommandResponseReadDir {
                result: Err(format!("{:?}", e)),
            },
            Ok(it) => CommandResponseReadDir {
                result: Ok(it.collect()),
            },
        }
    }
}
