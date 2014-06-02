﻿using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Api.Filesystem
{
    public class FilesystemProvider : IFilesystemProvider
    {
        private readonly string _rootPath;

        public FilesystemProvider(string rootPath)
        {
            _rootPath = rootPath;
        }

        public IList<string> ListRootDirectory(bool includeFiles = false, bool includeFolders = true)
        {
            if (includeFiles && includeFolders) return Directory.GetFileSystemEntries(_rootPath).ToList();
            if (includeFolders) return Directory.GetDirectories(_rootPath).ToList();
            if (includeFiles) return Directory.GetFiles(_rootPath).ToList();
            return new List<string>();
        }
    }
}
