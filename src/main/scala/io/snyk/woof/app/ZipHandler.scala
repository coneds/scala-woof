package io.snyk.woof.app

import com.google.common.io.ByteStreams
import com.google.common.io.MoreFiles
import com.google.common.io.RecursiveDeleteOption
import net.lingala.zip4j.core.ZipFile
import net.lingala.zip4j.model.FileHeader
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util
import java.util.stream.Collectors
import scala.collection.JavaConverters._

class ZipHandler {
  
  /**
   * Validates that a zip entry path is safe for extraction to the target directory.
   * Prevents Zip Slip attacks by checking for path traversal sequences and absolute paths.
   */
  private def validateEntryPath(entryName: String, targetDir: Path): Unit = {
    if (entryName == null || entryName.trim.isEmpty) {
      throw new SecurityException("Zip entry has null or empty path")
    }
    
    val normalizedName = entryName.replace('\\', '/')
    
    // Reject absolute paths
    if (normalizedName.startsWith("/")) {
      throw new SecurityException(s"Absolute path not allowed in zip entry: $entryName")
    }
    
    // Reject Windows absolute paths
    if (normalizedName.length >= 2 && normalizedName.charAt(1) == ':') {
      throw new SecurityException(s"Windows absolute path not allowed in zip entry: $entryName")
    }
    
    // Reject UNC paths
    if (entryName.startsWith("\\\\")) {
      throw new SecurityException(s"UNC path not allowed in zip entry: $entryName")
    }
    
    // Check for path traversal segments
    val segments = normalizedName.split('/')
    if (segments.exists(segment => segment == "..")) {
      throw new SecurityException(s"Path traversal sequence '..' not allowed in zip entry: $entryName")
    }
    
    // Canonical path verification - ultimate defense
    val resolvedPath = targetDir.resolve(normalizedName).normalize()
    val canonicalTarget = targetDir.toFile.getCanonicalFile
    val canonicalResolved = resolvedPath.toFile.getCanonicalFile
    
    val targetPath = canonicalTarget.toPath
    val resolvedCanonicalPath = canonicalResolved.toPath
    
    if (!resolvedCanonicalPath.startsWith(targetPath)) {
      throw new SecurityException(
        s"Zip entry path escapes target directory: $entryName " +
        s"(resolved to: ${canonicalResolved.getPath}, target: ${canonicalTarget.getPath})"
      )
    }
  }
  
  /**
   * Securely extracts a zip file, validating each entry path before extraction.
   */
  private def secureExtractAll(zip: ZipFile, targetDir: Path): Unit = {
    Files.createDirectories(targetDir)
    val canonicalTargetDir = targetDir.toFile.getCanonicalFile.toPath
    
    val headers: Seq[FileHeader] = zip.getFileHeaders
      .asScala
      .map(_.asInstanceOf[FileHeader])
      .toSeq
    
    for (header <- headers) {
      val entryName = header.getFileName
      
      // Validate the path before any extraction
      validateEntryPath(entryName, canonicalTargetDir)
      
      // Path is safe - proceed with extraction
      if (header.isDirectory) {
        val dirPath = canonicalTargetDir.resolve(entryName.replace('\\', '/')).normalize()
        Files.createDirectories(dirPath)
      } else {
        val normalizedEntry = entryName.replace('\\', '/')
        val filePath = canonicalTargetDir.resolve(normalizedEntry).normalize()
        Files.createDirectories(filePath.getParent)
        
        zip.extractFile(header, canonicalTargetDir.toAbsolutePath.toString)
      }
    }
  }

  @throws[Exception]
  def listTopLevelEntries(zipStream: InputStream): Array[String] = {
    val temp = Files.createTempFile("to-extract", ".zip").toFile
    try { // save our uploaded file in a temporary file
      {
        val os = new FileOutputStream(temp)
        try ByteStreams.copy(zipStream, os)
        finally if (os != null) os.close()
      }
      // open it as a zip file
      val zip = new ZipFile(temp)
      val tempDir = Files.createTempDirectory("woof")
      try { // extract the contents to a temporary directory
        secureExtractAll(zip, tempDir)
        // list the directory, and find the names of the items in it
        Files.list(tempDir).iterator.asScala.map((p: Path) => p.getFileName.toString).toArray
      } finally {
        // The temporary directory only contains zip entries.
        // Zip files do not support symlinks.
        // Hence, this is safe. (For real!)
        // Java 8 on OSX does not support secure deletion, so we have to
        // disable security.
        MoreFiles.deleteRecursively(tempDir, RecursiveDeleteOption.ALLOW_INSECURE)
      }
    } finally if (!temp.delete) System.err.println("temporary file cleanup failed: " + temp)
  }
}
