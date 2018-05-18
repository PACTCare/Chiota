#region Directives
using System;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Implementation Details:
// An implementation of a File and Folder Archiving and Compression class.
// Written by John Underhill, December 1, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Tools
{
    /// <summary>
    /// File and Folder Archiving and Compression
    /// </summary>
    public sealed class Compressor
    {
        #region Compression Header
        /// <summary>
        /// The compression header structure
        /// </summary>
        [Serializable]
        [StructLayout(LayoutKind.Sequential)]
        public struct CompressionHeader
        {
            /// <summary>
            /// The compression format
            /// </summary>
            public int Format;
            /// <summary>
            /// The number of compressed files
            /// </summary>
            public int FileCount;
            /// <summary>
            /// Length of an array of file names
            /// </summary>
            public int NameSize;
            /// <summary>
            /// An array containing the size of each file in the archive
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray)]
            public long[] FileSizes;
            /// <summary>
            /// An array containing the nameand subfolder path of each file in the archive
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray)]
            public char[] FileNames;

            /// <summary>
            /// Initialize the CompressionHeader structure
            /// </summary>
            /// 
            /// <param name="FileCount">The number of compressed files</param>
            /// <param name="NameSize">Length of an array of file names</param>
            /// <param name="FileSizes">An array containing the size of each file in the archive</param>
            /// <param name="FileNames">An array containing the name and subfolder path of each file in the archive</param>
            /// <param name="Format">The compression format</param>
            public CompressionHeader(int FileCount, int NameSize, long[] FileSizes, char[] FileNames, CompressionFormats Format)
            {
                this.Format = (int)Format;
                this.FileCount = FileCount;
                this.NameSize = NameSize;
                this.FileSizes = FileSizes;
                this.FileNames = FileNames;
            }
        }
        #endregion

        #region Enums
        /// <summary>
        /// Compression types
        /// </summary>
        public enum CompressionFormats : int
        {
            /// <summary>
            /// No compression
            /// </summary>
            None = 0,
            /// <summary>
            /// Deflate algorithm
            /// </summary>
            Deflate = 1,
            /// <summary>
            /// Gzip algorithm
            /// </summary>
            GZip = 2
        }
        #endregion

        #region Constants
        private const int MIN_HEADER = 22;
        private const int DEF_BLOCK = 1024;
        private const int SEEKTO_FORMAT = 0;
        private const int SEEKTO_COUNT = 4;
        private const int SEEKTO_NAMESZ = 8;
        private const int SEEKTO_SIZES = 12;
        #endregion

        #region Events
        /// <summary>
        /// Progress counter delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="e">Progress changed arguments</param>
        public delegate void ProgressCounterDelegate(object sender, ProgressChangedEventArgs e);

        /// <summary>
        /// Progress counter event
        /// </summary>
        [Description("Progress Counter")]
        public event ProgressCounterDelegate ProgressCounter;
        #endregion

        #region Public Properties
        /// <summary>
        /// Get: The working archive header
        /// </summary>
        public CompressionHeader ArchiveHeader { get; private set; }

        /// <summary>
        /// Get: The compression algorithm used to compress a file
        /// </summary>
        public CompressionFormats CompressionFormat { get; set; }

        /// <summary>
        /// Get: The working archive header
        /// </summary>
        public SearchOption FolderOption { get; private set; }
        #endregion

        #region Private Properties
        private int BlockSize { get; set; }
        private long FileSize { get; set; }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Format">Compression engine</param>
        /// <param name="FolderOption">Compression all folders or top directory only</param>
        public Compressor(CompressionFormats Format = CompressionFormats.Deflate, SearchOption FolderOption = SearchOption.AllDirectories)
        {
            CompressionFormat = Format;
            BlockSize = DEF_BLOCK;
            this.FolderOption = FolderOption;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Compress and archive a folder
        /// </summary>
        /// 
        /// <param name="InputPath">Folder path</param>
        /// 
        /// <returns>A stream containing the compressed bytes</returns>
        public MemoryStream CompressArchive(string InputPath)
        {
            if (!Directory.Exists(InputPath))
                throw new ArgumentException("InputPath: A valid folder path is required!");

            try
            {
                FileSize = GetFolderSize(InputPath, FolderOption);
                if (FileSize < 1) return null;
                BlockSize = GetBlockSize(FileSize);

                if (CompressionFormat == CompressionFormats.Deflate)
                    return CompressArchiveDf(InputPath);
                else if (CompressionFormat == CompressionFormats.GZip)
                    return CompressArchiveGz(InputPath);
                else
                    return CompressArchiveNc(InputPath);

            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Compress and archive a folder
        /// </summary>
        /// 
        /// <param name="InputPath">Folder path</param>
        /// <param name="OutputFile">The full path to new archive file</param>
        /// 
        /// <returns>Success</returns>
        public bool CompressArchive(string InputPath, string OutputFile)
        {
            if (!Directory.Exists(InputPath))
                throw new ArgumentException("InputPath: A valid folder path is required!");
            if (!Directory.Exists(Path.GetDirectoryName(OutputFile)))
                throw new ArgumentException("OutputFile: Invalid folder path!");

            try
            {
                FileSize = GetFolderSize(InputPath, FolderOption);
                if (FileSize < 1) return false;
                BlockSize = GetBlockSize(FileSize);

                if (CompressionFormat == CompressionFormats.Deflate)
                    CompressArchiveDf(InputPath, OutputFile);
                else if (CompressionFormat == CompressionFormats.GZip)
                    CompressArchiveGz(InputPath, OutputFile);
                else
                    CompressArchiveNc(InputPath, OutputFile);

                return true;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Decompress an archive
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the compressed archive</param>
        /// <param name="OutputPath">Destination directory for expanded files</param>
        /// 
        /// <returns>Success</returns>
        public bool DeCompressArchive(Stream InputStream, string OutputPath)
        {
            if (!Directory.Exists(OutputPath))
                throw new ArgumentException("OutputPath: A valid folder path is required!");

            try
            {
                CompressionFormats format = GetCompressionFormat(InputStream);
                FileSize = GetDeCompressedSize(InputStream);
                if (FileSize < 1) return false;
                BlockSize = GetBlockSize(FileSize);

                if (format == CompressionFormats.Deflate)
                    DeCompressArchiveDf(InputStream, OutputPath);
                else if (format == CompressionFormats.GZip)
                    DeCompressArchiveGz(InputStream, OutputPath);
                else
                    DeCompressArchiveNc(InputStream, OutputPath);

                return true;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Decompress an archive
        /// </summary>
        /// 
        /// <param name="InputFile">The full path to new archive file</param>
        /// <param name="OutputPath">Destination directory for expanded files</param>
        /// 
        /// <returns>Success</returns>
        public bool DeCompressArchive(string InputFile, string OutputPath)
        {
            if (!File.Exists(InputFile))
                throw new ArgumentException("InputFile: Invalid input file!");
            if (!Directory.Exists(OutputPath))
                throw new ArgumentException("OutputPath: A valid folder path is required!");

            try
            {
                CompressionFormats format = GetCompressionFormat(InputFile);
                FileSize = GetDeCompressedSize(InputFile);
                if (FileSize < 1) return false;
                BlockSize = GetBlockSize(FileSize);

                if (format == CompressionFormats.Deflate)
                    DeCompressArchiveDf(InputFile, OutputPath);
                else if (format == CompressionFormats.GZip)
                    DeCompressArchiveGz(InputFile, OutputPath);
                else
                    DeCompressArchiveNc(InputFile, OutputPath);

                return true;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Compress a file to a stream
        /// </summary>
        /// 
        /// <param name="InputFile">The full path to the compressed file</param>
        /// 
        /// <returns>A stream containing the compressed bytes</returns>
        public MemoryStream CompressFile(string InputFile)
        {
            if (!File.Exists(InputFile))
                throw new ArgumentException("InputFile: Invalid input file!");

            try
            {
                FileSize = GetFileSize(InputFile);
                if (FileSize < 1) return null;
                BlockSize = GetBlockSize(FileSize);

                if (CompressionFormat == CompressionFormats.Deflate)
                    return CompressFileDf(InputFile);
                else
                    return CompressFileGz(InputFile);
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Compress a file
        /// </summary>
        /// 
        /// <param name="InputFile">File to compress</param>
        /// <param name="OutputFile">Full path to destination file</param>
        /// 
        /// <returns>Success</returns>
        public bool CompressFile(string InputFile, string OutputFile)
        {
            if (!File.Exists(InputFile))
                throw new ArgumentException("InputFile: Invalid input file!");
            if (!Directory.Exists(Path.GetDirectoryName(OutputFile)))
                throw new ArgumentException("OutputFile: Invalid folder path!");

            try
            {
                FileSize = GetFileSize(InputFile);
                if (FileSize < 1) return false;
                BlockSize = GetBlockSize(FileSize);

                if (CompressionFormat == CompressionFormats.Deflate)
                    CompressFileDf(InputFile, OutputFile);
                else
                    CompressFileGz(InputFile, OutputFile);

                return true;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Decompress a file to a stream
        /// </summary>
        /// 
        /// <param name="InputFile">The full path to the compressed file</param>
        /// 
        /// <returns>The decompressed stream</returns>
        public MemoryStream DeCompressFile(string InputFile)
        {
            if (!File.Exists(InputFile))
                throw new ArgumentException("InputFile: Invalid input file!");

            try
            {
                FileSize = GetDeCompressedSize(InputFile);
                if (FileSize < 1) return null;
                BlockSize = GetBlockSize(FileSize);

                if (CompressionFormat == CompressionFormats.Deflate)
                    return DeCompressFileDf(InputFile);
                else
                    return DeCompressFileGz(InputFile);

            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Decompress a file
        /// </summary>
        /// 
        /// <param name="InputFile">Compressed file</param>
        /// <param name="OutputPath">Directory path destination</param>
        /// 
        /// <returns>Success</returns>
        public bool DeCompressFile(string InputFile, string OutputPath)
        {
            if (!File.Exists(InputFile))
                throw new ArgumentException("InputFile: Invalid input file!");
            if (!Directory.Exists(OutputPath))
                throw new ArgumentException("OutputPath: A valid folder path is required!");

            try
            {
                FileSize = GetDeCompressedSize(InputFile);
                if (FileSize < 1) return false;
                BlockSize = GetBlockSize(FileSize);

                if (CompressionFormat == CompressionFormats.Deflate)
                    DeCompressFileDf(InputFile, OutputPath);
                else
                    DeCompressFileGz(InputFile, OutputPath);

                return true;

            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Compress a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The stream to compress</param>
        /// 
        /// <returns>The compressed stream</returns>
        public MemoryStream CompressStream(Stream InputStream)
        {
            if (InputStream.Length < 1)
                throw new ArgumentException("InputStream: Invalid input stream!");

            try
            {
                FileSize = InputStream.Length;
                if (FileSize < 1) return null;
                BlockSize = GetBlockSize(FileSize);

                if (CompressionFormat == CompressionFormats.Deflate)
                    return CompressStreamDf(InputStream);
                else
                    return CompressStreamGz(InputStream);
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Decompress a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The stream to decompress</param>
        /// 
        /// <returns>The decompressed stream</returns>
        public MemoryStream DeCompressStream(Stream InputStream)
        {
            if (InputStream.Length < 1)
                throw new ArgumentException("InputStream: Invalid input stream!");

            try
            {
                FileSize = InputStream.Length;
                if (FileSize < 1) return null;
                BlockSize = GetBlockSize(FileSize);

                if (CompressionFormat == CompressionFormats.Deflate)
                    return DeCompressStreamDf(InputStream);
                else
                    return DeCompressStreamGz(InputStream);

            }
            catch
            {
                throw;
            }
        }
        #endregion

        #region Compression Header
        /// <summary>
        /// Create an empty Compression header
        /// </summary>
        /// 
        /// <param name="Format">The compression format</param>
        /// 
        /// <returns>An initialized CompressionHeader structure</returns>
        public static CompressionHeader CreateFileHeader(CompressionFormats Format = CompressionFormats.Deflate)
        {
            CompressionHeader header = new CompressionHeader();

            header.Format = (int)Format;
            header.FileCount = 0;
            header.NameSize = 0;
            header.FileSizes = new long[0];
            header.FileSizes[0] = 1;
            header.FileNames = new char[0];

            return header;
        }

        /// <summary>
        /// Create a Compression header from a file path
        /// </summary>
        /// 
        /// <param name="InputFile">The file to compress</param>
        /// <param name="Format">The compression format</param>
        /// 
        /// <returns>An initialized CompressionHeader structure</returns>
        public static CompressionHeader CreateFileHeader(string InputFile, CompressionFormats Format = CompressionFormats.Deflate)
        {
            if (!File.Exists(InputFile)) return new CompressionHeader();
            CompressionHeader header = new CompressionHeader();
            char[] name = Path.GetFileName(InputFile).ToCharArray();

            header.Format = (int)Format;
            header.FileCount = 1;
            header.NameSize = name.Length;
            header.FileSizes = new long[1];
            header.FileSizes[0] = GetFileSize(InputFile);
            header.FileNames = name;

            return header;
        }

        /// <summary>
        /// Create a Compression header from a folder path
        /// </summary>
        /// 
        /// <param name="InputPath">The file to compress</param>
        /// <param name="Format">The compression format</param>
        /// <param name="FolderOption">The scope of the folder compression; top level or all sub-folders</param>
        /// 
        /// <returns>An initialized CompressionHeader structure</returns>
        public static CompressionHeader CreateFolderHeader(string InputPath, CompressionFormats Format = CompressionFormats.Deflate, SearchOption FolderOption = SearchOption.AllDirectories)
        {
            if (!Directory.Exists(InputPath)) return new CompressionHeader();
            CompressionHeader header = new CompressionHeader();
            char[] names = GetNameArray(InputPath, FolderOption);

            header.Format = (int)Format;
            header.FileCount = GetFileCount(InputPath, FolderOption);
            header.NameSize = names.Length;
            header.FileSizes = GetFileSizes(InputPath, FolderOption);
            header.FileNames = names;

            return header;
        }
        #endregion

        #region Header Properties
        /// <summary>
        /// Get the decompressed size from a compressed file
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the compressed file</param>
        /// 
        /// <returns>The total size in bytes</returns>
        public static long GetDeCompressedSize(Stream InputStream)
        {
            CompressionHeader header = DeSerializeHeader(InputStream);
            long arcLen = 0;

            foreach (int sz in header.FileSizes)
                arcLen += sz;

            return arcLen;
        }

        /// <summary>
        /// Get the decompressed size from a compressed file
        /// </summary>
        /// 
        /// <param name="InputFile">The full path to the compressed file</param>
        /// 
        /// <returns>The total size in bytes</returns>
        public static long GetDeCompressedSize(string InputFile)
        {
            if (!File.Exists(InputFile)) return 0;
            long length = 0;

            using (BinaryReader reader = new BinaryReader(new FileStream(InputFile, FileMode.Open, FileAccess.Read, FileShare.Read)))
            {
                reader.BaseStream.Seek(SEEKTO_COUNT, SeekOrigin.Begin);
                int fileCount = reader.ReadInt32();
                long[] sizes = new long[fileCount];
                reader.BaseStream.Seek(SEEKTO_SIZES, SeekOrigin.Begin);
                int btSize = fileCount * 8;
                Buffer.BlockCopy(reader.ReadBytes(btSize), 0, sizes, 0, btSize);

                for (int i = 0; i < fileCount; i++)
                    length += sizes[i];
            }

            return length;
        }

        /// <summary>
        /// Get the compression format from a compressed file
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the compressed file</param>
        /// 
        /// <returns>The compression format type</returns>
        public static CompressionFormats GetCompressionFormat(Stream InputStream)
        {
            return (CompressionFormats)DeSerializeHeader(InputStream).Format;
        }

        /// <summary>
        /// Get the compression format from a compressed file
        /// </summary>
        /// 
        /// <param name="InputFile">The full path to the compressed file</param>
        /// 
        /// <returns>The compression format type</returns>
        public static CompressionFormats GetCompressionFormat(string InputFile)
        {
            if (!File.Exists(InputFile)) return 0;
            CompressionFormats flag = CompressionFormats.None;

            using (BinaryReader reader = new BinaryReader(new FileStream(InputFile, FileMode.Open, FileAccess.Read, FileShare.Read)))
            {
                reader.BaseStream.Seek(SEEKTO_FORMAT, SeekOrigin.Begin);
                flag = (CompressionFormats)reader.ReadInt32();
            }

            return flag;
        }

        /// <summary>
        /// Get the names of files contained in the compressed archive
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the compressed file</param>
        /// 
        /// <returns>A string containing the file names</returns>
        public static string GetFileNames(Stream InputStream)
        {
            return new string(DeSerializeHeader(InputStream).FileNames);
        }

        /// <summary>
        /// Get the names of files contained in the compressed archive
        /// </summary>
        /// 
        /// <param name="InputFile">The full path to the compressed file</param>
        /// 
        /// <returns>A string containing the file names</returns>
        public static string GetFileNames(string InputFile)
        {
            if (!File.Exists(InputFile)) return "";
            string names = "";

            using (BinaryReader reader = new BinaryReader(new FileStream(InputFile, FileMode.Open, FileAccess.Read, FileShare.Read)))
            {
                reader.BaseStream.Seek(SEEKTO_COUNT, SeekOrigin.Begin);
                int count = reader.ReadInt32();
                reader.BaseStream.Seek(SEEKTO_NAMESZ, SeekOrigin.Begin);
                int size = reader.ReadInt32();
                reader.BaseStream.Seek(SEEKTO_SIZES + (count * 8), SeekOrigin.Begin);
                names = new string(reader.ReadChars(size));
            }

            return names;
        }

        /// <summary>
        /// Get the byte length of the header file
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the compressed file</param>
        /// 
        /// <returns>The header size in bytes</returns>
        public static int GetHeaderLength(Stream InputStream)
        {
            InputStream.Seek(0, SeekOrigin.Begin);
            if (InputStream.Length < 1) return 0;
            int length = 12;
            InputStream.Seek(0, SeekOrigin.Begin);
            BinaryReader reader = new BinaryReader(InputStream);
            reader.BaseStream.Seek(SEEKTO_COUNT, SeekOrigin.Begin);
            int fileCount = reader.ReadInt32();
            length += fileCount * 8;
            int nameLen = reader.ReadInt32();
            length += nameLen;
            InputStream.Seek(0, SeekOrigin.Begin);

            return length;
        }

        /// <summary>
        /// Get the byte length of the header file
        /// </summary>
        /// 
        /// <param name="InputFile">The full path to the compressed file</param>
        /// 
        /// <returns>The header size in bytes</returns>
        public static int GetHeaderLength(string InputFile)
        {
            if (!File.Exists(InputFile)) return 0;
            int length = 12;

            using (BinaryReader reader = new BinaryReader(new FileStream(InputFile, FileMode.Open, FileAccess.Read, FileShare.Read)))
            {
                reader.BaseStream.Seek(SEEKTO_COUNT, SeekOrigin.Begin);

                int fileCount = reader.ReadInt32();
                length += fileCount * 8;
                int nameLen = reader.ReadInt32();
                length += nameLen;
            }

            return length;
        }
        #endregion

        #region Header Serialization
        /// <summary>
        /// Read a compression header from a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The data stream</param>
        /// 
        /// <returns>An initialized CompressionHeaderStruct</returns>
        public static CompressionHeader DeSerializeHeader(Stream InputStream)
        {
            InputStream.Seek(0, SeekOrigin.Begin);
            CompressionHeader Header = new CompressionHeader();
            if (InputStream.Length < MIN_HEADER) return Header;

            BinaryReader reader = new BinaryReader(InputStream);
            
            // compression format
            Header.Format = reader.ReadInt32();
            // get file count
            int fileCount = reader.ReadInt32();
            Header.FileCount = fileCount;
            // file name array length
            int nameLen = reader.ReadInt32();
            Header.NameSize = nameLen;
            // get start positions in the file
            int btCount = fileCount * 8;
            byte[] temp = reader.ReadBytes(btCount);
            Header.FileSizes = Convert(temp);
            // get file name array
            Header.FileNames = reader.ReadChars(nameLen);
            InputStream.Seek(0, SeekOrigin.Begin);

            return Header;
        }

        /// <summary>
        /// Read a compression header from a file path
        /// </summary>
        /// 
        /// <param name="InputFile">The full path to the input file</param>
        /// 
        /// <returns>An initialized CompressionHeaderStruct</returns>
        public static CompressionHeader DeSerializeHeader(string InputFile)
        {
            CompressionHeader Header = new CompressionHeader();
            if (!File.Exists(InputFile)) return Header;

            using (BinaryReader reader = new BinaryReader(new FileStream(InputFile, FileMode.Open, FileAccess.Read, FileShare.Read)))
            {
                // compression format
                Header.Format = reader.ReadInt32();
                // get file count
                int fileCount = reader.ReadInt32();
                Header.FileCount = fileCount;
                // file name array length
                int nameLen = reader.ReadInt32();
                Header.NameSize = nameLen;
                // get start positions in the file
                int btCount = fileCount * 8;
                byte[] temp = reader.ReadBytes(btCount);
                Header.FileSizes = Convert(temp);
                // get file name array
                Header.FileNames = reader.ReadChars(nameLen);
            }

            return Header;
        }

        /// <summary>
        /// Serialize a CompressionHeaderStruct
        /// </summary>
        /// 
        /// <param name="Header">The initialized CompressionHeaderStruct</param>
        /// 
        /// <returns>The struct as a stream of bytes</returns>
        public static MemoryStream SerializeHeader(CompressionHeader Header)
        {
            try
            {
                MemoryStream stream = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(stream);

                // write compression format
                writer.Write(Header.Format);
                // write file count
                writer.Write(Header.FileCount);
                // write name array length
                writer.Write(Header.FileNames.Length);
                // write positions aray
                byte[] temp = Convert(Header.FileSizes);
                writer.Write(temp);
                // write file names array
                writer.Write(Header.FileNames);
                stream.Seek(0, SeekOrigin.Begin);

                return stream;
            }
            catch
            {
                return new MemoryStream();
            }
        }
        #endregion

        #region File Compression
        private MemoryStream CompressFileDf(string InputPath)
        {
            ArchiveHeader = CreateFileHeader(InputPath);
            byte[] headerStream = SerializeHeader(ArchiveHeader).ToArray();
            MemoryStream dataStream = new MemoryStream();

            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read)))
            {
                byte[] inputBuffer = new byte[BlockSize];
                long bytesRead = 0;
                long bytesTotal = 0;

                using (DeflateStream cmpStream = new DeflateStream(dataStream, CompressionMode.Compress))
                {
                    cmpStream.BaseStream.Write(headerStream, 0, headerStream.Length);

                    while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                    {
                        cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                        bytesTotal += bytesRead;
                        CalculateProgress(bytesTotal);
                    }
                }
            }

            return dataStream;
        }

        private void CompressFileDf(string InputPath, string OutputPath)
        {
            ArchiveHeader = CreateFileHeader(InputPath);
            byte[] headerStream = SerializeHeader(ArchiveHeader).ToArray();

            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read)))
            {
                byte[] inputBuffer = new byte[BlockSize];
                long bytesRead = 0;
                long bytesTotal = 0;

                using (DeflateStream cmpStream = new DeflateStream(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.Read), CompressionMode.Compress))
                {
                    cmpStream.BaseStream.Write(headerStream, 0, headerStream.Length);

                    while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                    {
                        cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                        bytesTotal += bytesRead;
                        CalculateProgress(bytesTotal);
                    }
                }
                
            }
        }

        private MemoryStream CompressFileGz(string InputPath)
        {
            ArchiveHeader = CreateFileHeader(InputPath);
            byte[] headerStream = SerializeHeader(ArchiveHeader).ToArray();
            MemoryStream dataStream = new MemoryStream();

            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read)))
            {
                byte[] inputBuffer = new byte[BlockSize];
                long bytesRead = 0;
                long bytesTotal = 0;

                using (GZipStream cmpStream = new GZipStream(dataStream, CompressionMode.Compress))
                {
                    cmpStream.BaseStream.Write(headerStream, 0, headerStream.Length);

                    while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                    {
                        cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                        bytesTotal += bytesRead;
                        CalculateProgress(bytesTotal);
                    }
                }
            }

            return dataStream;
        }

        private void CompressFileGz(string InputPath, string OutputPath)
        {
            ArchiveHeader = CreateFileHeader(InputPath);
            byte[] headerStream = SerializeHeader(ArchiveHeader).ToArray();

            using (BinaryReader inputReader = new BinaryReader(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read)))
            {
                byte[] inputBuffer = new byte[BlockSize];
                long bytesRead = 0;
                long bytesTotal = 0;

                using (GZipStream cmpStream = new GZipStream(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.Read), CompressionMode.Compress))
                {
                    cmpStream.BaseStream.Write(headerStream, 0, headerStream.Length);

                    while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                    {
                        cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                        bytesTotal += bytesRead;
                        CalculateProgress(bytesTotal);
                    }
                }
            }
        }

        private MemoryStream CompressStreamDf(Stream InputStream)
        {
            MemoryStream dataStream = new MemoryStream();
            BinaryReader inputReader = new BinaryReader(InputStream);
            byte[] inputBuffer = new byte[BlockSize];
            long bytesRead = 0;
            long bytesTotal = 0;

            using (DeflateStream cmpStream = new DeflateStream(dataStream, CompressionMode.Compress, true))
            {
                while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                {
                    cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                    bytesTotal += bytesRead;
                    CalculateProgress(bytesTotal);
                }
            }

            return dataStream;
        }

        private MemoryStream CompressStreamGz(Stream InputStream)
        {
            MemoryStream dataStream = new MemoryStream();
            BinaryReader inputReader = new BinaryReader(InputStream);
            byte[] inputBuffer = new byte[BlockSize];
            long bytesRead = 0;
            long bytesTotal = 0;

            using (GZipStream cmpStream = new GZipStream(dataStream, CompressionMode.Compress, true))
            {
                while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                {
                    cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                    bytesTotal += bytesRead;
                    CalculateProgress(bytesTotal);
                }
            }

            return dataStream;
        }

        private MemoryStream DeCompressFileDf(string InputPath)
        {
            byte[] inputBuffer = new byte[BlockSize];
            long bytesRead = 0;
            long bytesTotal = 0;
            string fileName = GetFileNames(InputPath);
            int offset = GetHeaderLength(InputPath);
            MemoryStream dataStream = new MemoryStream();
            BinaryWriter outputWriter = new BinaryWriter(dataStream);
            ArchiveHeader = DeSerializeHeader(InputPath);

            using (DeflateStream cmpStream = new DeflateStream(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read), CompressionMode.Decompress))
            {
                cmpStream.BaseStream.Position = offset;

                while ((bytesRead = cmpStream.Read(inputBuffer, 0, BlockSize)) > 0)
                {
                    outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                    bytesTotal += bytesRead;
                    CalculateProgress(bytesTotal);
                }
            }

            return dataStream;
        }

        private void DeCompressFileDf(string InputPath, string OutputPath)
        {
            byte[] inputBuffer = new byte[BlockSize];
            long bytesRead = 0;
            long bytesTotal = 0;
            string fileName = GetFileNames(InputPath);
            int offset = GetHeaderLength(InputPath);
            string path = GetUniquePath(Path.Combine(OutputPath, fileName));
            ArchiveHeader = DeSerializeHeader(InputPath);

            using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read)))
            {
                using (DeflateStream cmpStream = new DeflateStream(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read), CompressionMode.Decompress))
                {
                    cmpStream.BaseStream.Position = offset;

                    while ((bytesRead = cmpStream.Read(inputBuffer, 0, BlockSize)) > 0)
                    {
                        outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                        bytesTotal += bytesRead;
                        CalculateProgress(bytesTotal);
                    }
                }
            }
        }

        private MemoryStream DeCompressFileGz(string InputPath)
        {
            byte[] inputBuffer = new byte[BlockSize];
            long bytesRead = 0;
            long bytesTotal = 0;
            string fileName = GetFileNames(InputPath);
            int offset = GetHeaderLength(InputPath);
            MemoryStream dataStream = new MemoryStream();
            BinaryWriter outputWriter = new BinaryWriter(dataStream);
            ArchiveHeader = DeSerializeHeader(InputPath);

            using (GZipStream cmpStream = new GZipStream(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read), CompressionMode.Decompress))
            {
                cmpStream.BaseStream.Position = offset;

                while ((bytesRead = cmpStream.Read(inputBuffer, 0, BlockSize)) > 0)
                {
                    outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                    bytesTotal += bytesRead;
                    CalculateProgress(bytesTotal);
                }
            }

            return dataStream;
        }

        private void DeCompressFileGz(string InputPath, string OutputPath)
        {
            byte[] inputBuffer = new byte[BlockSize];
            long bytesRead = 0;
            long bytesTotal = 0;
            string fileName = GetFileNames(InputPath);
            int offset = GetHeaderLength(InputPath);
            string path = GetUniquePath(Path.Combine(OutputPath, fileName));
            ArchiveHeader = DeSerializeHeader(InputPath);

            using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read)))
            {
                using (GZipStream cmpStream = new GZipStream(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read), CompressionMode.Decompress))
                {
                    cmpStream.BaseStream.Position = offset;

                    while ((bytesRead = cmpStream.Read(inputBuffer, 0, BlockSize)) > 0)
                    {
                        outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                        bytesTotal += bytesRead;
                        CalculateProgress(bytesTotal);
                    }
                }
            }
        }

        private MemoryStream DeCompressStreamDf(Stream InputStream)
        {
            byte[] inputBuffer = new byte[BlockSize];
            long bytesRead = 0;
            long bytesTotal = 0;
            MemoryStream dataStream = new MemoryStream();
            BinaryWriter outputWriter = new BinaryWriter(dataStream);

            using (DeflateStream cmpStream = new DeflateStream(InputStream, CompressionMode.Decompress))
            {
                while ((bytesRead = cmpStream.Read(inputBuffer, 0, BlockSize)) > 0)
                {
                    outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                    bytesTotal += bytesRead;
                    CalculateProgress(bytesTotal);
                }
            }

            return dataStream;
        }

        private MemoryStream DeCompressStreamGz(Stream InputStream)
        {
            byte[] inputBuffer = new byte[BlockSize];
            long bytesRead = 0;
            long bytesTotal = 0;
            MemoryStream dataStream = new MemoryStream();
            BinaryWriter outputWriter = new BinaryWriter(dataStream);

            using (GZipStream cmpStream = new GZipStream(InputStream, CompressionMode.Decompress))
            {
                while ((bytesRead = cmpStream.Read(inputBuffer, 0, BlockSize)) > 0)
                {
                    outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                    bytesTotal += bytesRead;
                    CalculateProgress(bytesTotal);
                }
            }

            return dataStream;
        }
        #endregion

        #region Folder Archiving
        private MemoryStream CompressArchiveDf(string InputPath)
        {
            ArchiveHeader = CreateFolderHeader(InputPath, CompressionFormat, FolderOption);
            byte[] headerStream = SerializeHeader(ArchiveHeader).ToArray();
            string[] paths = GetFilePaths(InputPath, FolderOption);
            long[] sizes = new long[paths.Length];
            byte[] inputBuffer = new byte[BlockSize];
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;
            MemoryStream dataStream = new MemoryStream();

            using (DeflateStream cmpStream = new DeflateStream(dataStream, CompressionMode.Compress, true))
            {
                cmpStream.BaseStream.Write(headerStream, 0, headerStream.Length);

                for (int i = 0; i < paths.Length; i++)
                {
                    using (BinaryReader inputReader = new BinaryReader(new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.Read)))
                    {
                        while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                        {
                            cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;
                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }
                    sizes[i] = byteCount;
                    byteCount = 0;
                }
            }

            return dataStream;
        }

        private void CompressArchiveDf(string InputPath, string OutputPath)
        {
            ArchiveHeader = CreateFolderHeader(InputPath, CompressionFormat, FolderOption);
            byte[] headerStream = SerializeHeader(ArchiveHeader).ToArray();
            string[] paths = GetFilePaths(InputPath, FolderOption);
            long[] sizes = new long[paths.Length];
            byte[] inputBuffer = new byte[BlockSize];
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;

            using (DeflateStream cmpStream = new DeflateStream(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.Read), CompressionMode.Compress))
            {
                cmpStream.BaseStream.Write(headerStream, 0, headerStream.Length);

                for (int i = 0; i < paths.Length; i++)
                {
                    using (BinaryReader inputReader = new BinaryReader(new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.Read)))
                    {
                        while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                        {
                            cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;
                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }
                    sizes[i] = byteCount;
                    byteCount = 0;
                }
            }
        }

        private MemoryStream CompressArchiveGz(string InputPath)
        {
            ArchiveHeader = CreateFolderHeader(InputPath, CompressionFormat, FolderOption);
            byte[] headerStream = SerializeHeader(ArchiveHeader).ToArray();
            string[] paths = GetFilePaths(InputPath, FolderOption);
            long[] sizes = new long[paths.Length];
            byte[] inputBuffer = new byte[BlockSize];
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;
            MemoryStream dataStream = new MemoryStream();

            using (GZipStream cmpStream = new GZipStream(dataStream, CompressionMode.Compress, true))
            {
                cmpStream.BaseStream.Write(headerStream, 0, headerStream.Length);

                for (int i = 0; i < paths.Length; i++)
                {
                    using (BinaryReader inputReader = new BinaryReader(new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.Read)))
                    {
                        while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                        {
                            cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;
                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }

                    sizes[i] = byteCount;
                    byteCount = 0;
                }
            }

            return dataStream;
        }

        private void CompressArchiveGz(string InputPath, string OutputPath)
        {
            ArchiveHeader = CreateFolderHeader(InputPath, CompressionFormat, FolderOption);
            byte[] headerStream = SerializeHeader(ArchiveHeader).ToArray();
            string[] paths = GetFilePaths(InputPath, FolderOption);
            long[] sizes = new long[paths.Length];
            byte[] inputBuffer = new byte[BlockSize];
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;

            using (GZipStream cmpStream = new GZipStream(new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.Read), CompressionMode.Compress))
            {
                cmpStream.BaseStream.Write(headerStream, 0, headerStream.Length);

                for (int i = 0; i < paths.Length; i++)
                {
                    using (BinaryReader inputReader = new BinaryReader(new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.Read)))
                    {
                        while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                        {
                            cmpStream.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;
                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }

                    sizes[i] = byteCount;
                    byteCount = 0;
                }
            }
        }

        private MemoryStream CompressArchiveNc(string InputPath)
        {
            ArchiveHeader = CreateFolderHeader(InputPath, CompressionFormat, FolderOption);
            byte[] headerStream = SerializeHeader(ArchiveHeader).ToArray();
            string[] paths = GetFilePaths(InputPath, FolderOption);
            long[] sizes = new long[paths.Length];
            byte[] inputBuffer = new byte[BlockSize];
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;
            MemoryStream dataStream = new MemoryStream();

            dataStream.Write(headerStream, 0, headerStream.Length);

            for (int i = 0; i < paths.Length; i++)
            {
                using (BinaryReader inputReader = new BinaryReader(new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.Read)))
                {
                    while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                    {
                        dataStream.Write(inputBuffer, 0, (int)bytesRead);
                        byteCount += bytesRead;
                        bytesTotal += bytesRead;
                        CalculateProgress(bytesTotal);
                    }
                }

                sizes[i] = byteCount;
                byteCount = 0;
            }

            return dataStream;
        }

        private void CompressArchiveNc(string InputPath, string OutputPath)
        {
            ArchiveHeader = CreateFolderHeader(InputPath, CompressionFormat, FolderOption);
            byte[] headerStream = SerializeHeader(ArchiveHeader).ToArray();
            string[] paths = GetFilePaths(InputPath, FolderOption);
            long[] sizes = new long[paths.Length];
            byte[] inputBuffer = new byte[BlockSize];
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;

            using (FileStream outputStream = new FileStream(OutputPath, FileMode.Create, FileAccess.Write, FileShare.Read))
            {
                outputStream.Write(headerStream, 0, headerStream.Length);

                for (int i = 0; i < paths.Length; i++)
                {
                    using (BinaryReader inputReader = new BinaryReader(new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.Read)))
                    {
                        while ((bytesRead = inputReader.Read(inputBuffer, 0, BlockSize)) > 0)
                        {
                            outputStream.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;
                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }

                    sizes[i] = byteCount;
                    byteCount = 0;
                }
            }
        }

        private void DeCompressArchiveDf(Stream InputStream, string OutputPath)
        {
            ArchiveHeader = DeSerializeHeader(InputStream);
            string names = new string(ArchiveHeader.FileNames);
            string[] fileNames = names.Split('*');
            byte[] inputBuffer = new byte[BlockSize];
            int offset = GetHeaderLength(InputStream);
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;
            int bytesOut = BlockSize;
            long fileSize = 0;

            using (DeflateStream cmpStream = new DeflateStream(InputStream, CompressionMode.Decompress))
            {
                cmpStream.BaseStream.Position = offset;

                for (int i = 0; i < ArchiveHeader.FileCount; i++)
                {
                    string path = GetUniquePath(Path.Combine(OutputPath, fileNames[i]));
                    if (!Directory.Exists(Path.GetDirectoryName(path)))
                        Directory.CreateDirectory(Path.GetDirectoryName(path));

                    fileSize = ArchiveHeader.FileSizes[i];
                    byteCount = 0;

                    if (fileSize < BlockSize)
                        bytesOut = (int)fileSize;
                    else
                        bytesOut = BlockSize;

                    using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read)))
                    {
                        while ((bytesRead = cmpStream.Read(inputBuffer, 0, bytesOut)) > 0)
                        {
                            outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;

                            if (byteCount + BlockSize > fileSize)
                                bytesOut = (int)(fileSize - byteCount);

                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }
                }
            }
        }

        private void DeCompressArchiveDf(string InputPath, string OutputPath)
        {
            ArchiveHeader = DeSerializeHeader(InputPath);
            string names = new string(ArchiveHeader.FileNames);
            string[] fileNames = names.Split('*');
            byte[] inputBuffer = new byte[BlockSize];
            int offset = GetHeaderLength(InputPath);
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;
            int bytesOut = BlockSize;
            long fileSize = 0;

            using (DeflateStream cmpStream = new DeflateStream(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read), CompressionMode.Decompress))
            {
                cmpStream.BaseStream.Position = offset;

                for (int i = 0; i < ArchiveHeader.FileCount; i++)
                {
                    string path = GetUniquePath(Path.Combine(OutputPath, fileNames[i]));
                    fileSize = ArchiveHeader.FileSizes[i];
                    byteCount = 0;

                    if (fileSize < BlockSize)
                        bytesOut = (int)fileSize;
                    else
                        bytesOut = BlockSize;

                    using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read)))
                    {
                        while ((bytesRead = cmpStream.Read(inputBuffer, 0, bytesOut)) > 0)
                        {
                            outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;

                            if (byteCount + BlockSize > fileSize)
                                bytesOut = (int)(fileSize - byteCount);

                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }
                }
            }
        }

        private void DeCompressArchiveGz(Stream InputStream, string OutputPath)
        {
            ArchiveHeader = DeSerializeHeader(InputStream);
            string names = new string(ArchiveHeader.FileNames);
            string[] fileNames = names.Split('*');
            byte[] inputBuffer = new byte[BlockSize];
            int offset = GetHeaderLength(InputStream);
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;
            int bytesOut = BlockSize;
            long fileSize = 0;

            using (GZipStream cmpStream = new GZipStream(InputStream, CompressionMode.Decompress))
            {
                cmpStream.BaseStream.Position = offset;

                for (int i = 0; i < ArchiveHeader.FileCount; i++)
                {
                    string path = GetUniquePath(Path.Combine(OutputPath, fileNames[i]));
                    fileSize = ArchiveHeader.FileSizes[i];
                    byteCount = 0;

                    if (fileSize < BlockSize)
                        bytesOut = (int)fileSize;
                    else
                        bytesOut = BlockSize;

                    using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read)))
                    {
                        while ((bytesRead = cmpStream.Read(inputBuffer, 0, bytesOut)) > 0)
                        {
                            outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;

                            if (byteCount + BlockSize > fileSize)
                                bytesOut = (int)(fileSize - byteCount);

                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }
                }
            }

        }

        private void DeCompressArchiveGz(string InputPath, string OutputPath)
        {
            ArchiveHeader = DeSerializeHeader(InputPath);
            string names = new string(ArchiveHeader.FileNames);
            string[] fileNames = names.Split('*');
            byte[] inputBuffer = new byte[BlockSize];
            int offset = GetHeaderLength(InputPath);
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;
            int bytesOut = BlockSize;
            long fileSize = 0;

            using (GZipStream cmpStream = new GZipStream(new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read), CompressionMode.Decompress))
            {
                cmpStream.BaseStream.Position = offset;

                for (int i = 0; i < ArchiveHeader.FileCount; i++)
                {
                    string path = GetUniquePath(Path.Combine(OutputPath, fileNames[i]));
                    fileSize = ArchiveHeader.FileSizes[i];
                    byteCount = 0;

                    if (fileSize < BlockSize)
                        bytesOut = (int)fileSize;
                    else
                        bytesOut = BlockSize;

                    using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read)))
                    {
                        while ((bytesRead = cmpStream.Read(inputBuffer, 0, bytesOut)) > 0)
                        {
                            outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;

                            if (byteCount + BlockSize > fileSize)
                                bytesOut = (int)(fileSize - byteCount);

                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }
                }
            }
            
        }

        private void DeCompressArchiveNc(Stream InputStream, string OutputPath)
        {
            ArchiveHeader = DeSerializeHeader(InputStream);
            string names = new string(ArchiveHeader.FileNames);
            string[] fileNames = names.Split('*');
            byte[] inputBuffer = new byte[BlockSize];
            int offset = GetHeaderLength(InputStream);
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;
            int bytesOut = BlockSize;
            long fileSize = 0;

            InputStream.Position = offset;

            for (int i = 0; i < ArchiveHeader.FileCount; i++)
            {
                string path = GetUniquePath(Path.Combine(OutputPath, fileNames[i]));
                fileSize = ArchiveHeader.FileSizes[i];
                byteCount = 0;

                if (fileSize < BlockSize)
                    bytesOut = (int)fileSize;
                else
                    bytesOut = BlockSize;

                using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read)))
                {
                    while ((bytesRead = InputStream.Read(inputBuffer, 0, bytesOut)) > 0)
                    {
                        outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                        byteCount += bytesRead;

                        if (byteCount + BlockSize > fileSize)
                            bytesOut = (int)(fileSize - byteCount);

                        bytesTotal += bytesRead;
                        CalculateProgress(bytesTotal);
                    }
                }
            }
        }

        private void DeCompressArchiveNc(string InputPath, string OutputPath)
        {
            ArchiveHeader = DeSerializeHeader(InputPath);
            string names = new string(ArchiveHeader.FileNames);
            string[] fileNames = names.Split('*');
            byte[] inputBuffer = new byte[BlockSize];
            int offset = GetHeaderLength(InputPath);
            long byteCount = 0;
            long bytesRead = 0;
            long bytesTotal = 0;
            int bytesOut = BlockSize;
            long fileSize = 0;

            using (FileStream inputStream = new FileStream(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                inputStream.Position = offset;

                for (int i = 0; i < ArchiveHeader.FileCount; i++)
                {
                    string path = GetUniquePath(Path.Combine(OutputPath, fileNames[i]));
                    fileSize = ArchiveHeader.FileSizes[i];
                    byteCount = 0;

                    if (fileSize < BlockSize)
                        bytesOut = (int)fileSize;
                    else
                        bytesOut = BlockSize;

                    using (BinaryWriter outputWriter = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read)))
                    {
                        while ((bytesRead = inputStream.Read(inputBuffer, 0, bytesOut)) > 0)
                        {
                            outputWriter.Write(inputBuffer, 0, (int)bytesRead);
                            byteCount += bytesRead;

                            if (byteCount + BlockSize > fileSize)
                                bytesOut = (int)(fileSize - byteCount);

                            bytesTotal += bytesRead;
                            CalculateProgress(bytesTotal);
                        }
                    }
                }
            }
        }
        #endregion

        #region Helpers
        private void CalculateProgress(long ByteCount)
        {
            if (ProgressCounter != null)
            {
                double progress = 100.0 * (double)ByteCount / FileSize;
                ProgressCounter(this, new ProgressChangedEventArgs((int)progress, (object)ByteCount));
            }
        }

        private static long[] Convert(byte[] Data)
        {
            int inCount = Data.Length / 8;
            long[] temp = new long[inCount];
            Buffer.BlockCopy(Data, 0, temp, 0, Data.Length);

            return temp;
        }

        private static byte[] Convert(int[] Data)
        {
            int btCount = Data.Length * 4;
            byte[] temp = new byte[btCount];
            Buffer.BlockCopy(Data, 0, temp, 0, btCount);

            return temp;
        }

        private static byte[] Convert(long[] Data)
        {
            int btCount = Data.Length * 8;
            byte[] temp = new byte[btCount];
            Buffer.BlockCopy(Data, 0, temp, 0, btCount);

            return temp;
        }

        private static int GetBlockSize(long DataSize)
        {
            int size = (int)DataSize / 100;
            if (size < 64000)
                size = (int)DataSize / 4;

            return size < 1 ? DEF_BLOCK : size;
        }

        private static int GetFileCount(string InputPath, SearchOption FolderOption = SearchOption.AllDirectories)
        {
            DirectoryInfo dir = new DirectoryInfo(InputPath);
            FileInfo[] files = dir.GetFiles("*.*", FolderOption);

            return files.Length;
        }

        private static string[] GetFilePaths(string InputPath, SearchOption FolderOption = SearchOption.AllDirectories)
        {
            DirectoryInfo dir = new DirectoryInfo(InputPath);
            FileInfo[] files = dir.GetFiles("*.*", FolderOption);
            string[] fileList = new string[files.Length];

            for (int i = 0; i < fileList.Length; i++)
                fileList[i] = files[i].FullName;

            return fileList;
        }

        private static string[] GetFileSubPaths(string InputPath, SearchOption FolderOption = SearchOption.AllDirectories)
        {
            int offset = InputPath.LastIndexOf(@"\");
            DirectoryInfo dir = new DirectoryInfo(InputPath);
            FileInfo[] files = dir.GetFiles("*.*", FolderOption);
            string[] fileList = new string[files.Length];

            for (int i = 0; i < fileList.Length; i++)
                fileList[i] = Path.Combine(files[i].Directory.FullName.Substring(offset), files[i].Name);

            return fileList;
        }

        private static long GetFileSize(string InputFile)
        {
            FileInfo file = new FileInfo(InputFile);
            return file.Length;
        }

        private static long[] GetFileSizes(string InputPath, SearchOption FolderOption = SearchOption.AllDirectories)
        {
            DirectoryInfo dir = new DirectoryInfo(InputPath);
            FileInfo[] files = dir.GetFiles("*.*", FolderOption);
            long[] fileSizes = new long[files.Length];

            for (int i = 0; i < files.Length; i++)
                fileSizes[i] = files[i].Length;

            return fileSizes;
        }

        private static long GetFolderSize(string InputPath, SearchOption FolderOption = SearchOption.AllDirectories)
        {
            DirectoryInfo dir = new DirectoryInfo(InputPath);
            FileInfo[] files = dir.GetFiles("*.*", FolderOption);
            long filesTotal = 0;

            for (int i = 0; i < files.Length; i++)
                filesTotal += files[i].Length;

            return filesTotal;
        }

        private static char[] GetNameArray(string InputPath, SearchOption FolderOption = SearchOption.AllDirectories)
        {
            DirectoryInfo dir = new DirectoryInfo(InputPath);
            FileInfo[] info = dir.GetFiles("*.*", FolderOption);
            string files = "";
            int offset = InputPath.LastIndexOf(@"\") + 1;

            for (int i = 0; i < info.Length; i++)
            {
                string spfl = Path.Combine(info[i].Directory.FullName.Substring(offset), info[i].Name);
                if (i < info.Length - 1)
                    files += spfl + "*";
                else
                    files += spfl;
            }

            return files.ToCharArray();
        }

        private static string GetUniquePath(string FilePath)
        {
            string directory = Path.GetDirectoryName(FilePath);
            string fileName = Path.GetFileNameWithoutExtension(FilePath);
            string extension = Path.GetExtension(FilePath);

            for (int j = 1; j < 101; j++)
            {
                // test unique names
                if (File.Exists(FilePath))
                    FilePath = Path.Combine(directory, fileName + j.ToString() + extension);
                else
                    break;
            }
            return FilePath;
        }
        #endregion
    }
}
