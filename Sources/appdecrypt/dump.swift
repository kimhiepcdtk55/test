//
//  Dump.swift
//  appdump
//
//  Created by paradiseduo on 2021/7/29.
//

import Foundation
import MachO

@_silgen_name("mremap_encrypted")
func mremap_encrypted(_: UnsafeMutableRawPointer, _: Int, _: UInt32, _: UInt32, _: UInt32) -> Int32

class Dump {
    let consoleIO = ConsoleIO()
    var targetUrl = ""
    
    func staticMode() {
        if CommandLine.argc < 3 {
            consoleIO.printUsage()
            return
        }
        if CommandLine.arguments.contains(where: { $0 == "-h" || $0 == "--help" }) {
            consoleIO.printUsage()
            return
        }
        
        let fileManager = FileManager.default
        var sourceUrl = CommandLine.arguments[1]
        if sourceUrl.hasSuffix("/") {
            sourceUrl.removeLast()
        }
        targetUrl = CommandLine.arguments[2]
        if targetUrl.hasSuffix("/") {
            targetUrl.removeLast()
        }
        
        var ignoreIOSOnlyCheck = false
        ignoreIOSOnlyCheck = CommandLine.arguments.contains("--ignore-ios-check")
        
        #if os(iOS)
        if !targetUrl.hasSuffix("/Payload") {
            targetUrl += "/Payload"
        }
        #endif
        
        do {
            consoleIO.writeMessage("Copy From \(sourceUrl) to \(targetUrl)")
            var isDirectory: ObjCBool = false
            if fileManager.fileExists(atPath: targetUrl, isDirectory: &isDirectory) {
                if isDirectory.boolValue && !targetUrl.hasSuffix(".app") {
                    consoleIO.writeMessage("\(targetUrl) is a Directory")
                } else {
                    try fileManager.removeItem(atPath: targetUrl)
                    consoleIO.writeMessage("Success to remove \(targetUrl)")
                }
            }
            try fileManager.copyItem(atPath: sourceUrl, toPath: targetUrl)
            consoleIO.writeMessage("Success to copy file.")
        } catch let e {
            consoleIO.writeMessage("Failed With \(e)", to: .error)
        }
        
        var needDumpFilePaths = [String]()
        var dumpedFilePaths = [String]()
        
        // 1. Tìm Mach-O files bằng phương pháp gốc (qua extension)
        let enumeratorAtPath = fileManager.enumerator(atPath: sourceUrl)
        if let arr = enumeratorAtPath?.allObjects as? [String] {
            for item in arr {
                if item.hasSuffix(".app") {
                    let machOName = item.components(separatedBy: "/").last?.components(separatedBy: ".app").first ?? ""
                    if machOName == "" {
                        consoleIO.writeMessage("Can't find machO name.", to: .error)
                        return
                    }
                    #if os(OSX)
                    let machOFile = sourceUrl+"/"+item+"/"+machOName
                    let task = Process()
                    task.launchPath = "/usr/bin/otool"
                    task.arguments = ["-l", machOFile]
                    let pipe = Pipe()
                    task.standardOutput = pipe
                    task.launch()
                    let data = pipe.fileHandleForReading.readDataToEndOfFile()
                    if let output = String(data: data, encoding: String.Encoding.utf8) {
                        if output.contains("LC_VERSION_MIN_IPHONEOS") || output.contains("platform 2") {
                            if !ignoreIOSOnlyCheck {
                                consoleIO.writeMessage("This app can't run on Mac M1 ! However, you can decrypt it anyway by adding argument --ignore-ios-check")
                                do { try fileManager.removeItem(atPath: targetUrl) } catch {}
                                exit(-10)
                            } else {
                                consoleIO.writeMessage("Warning ! The app is will not run on M1 Mac. Decrypting it anyway.")
                            }
                        }
                    }
                    #endif
                    needDumpFilePaths.append(sourceUrl+"/"+item+"/"+machOName)
                    dumpedFilePaths.append(targetUrl+"/"+item+"/"+machOName)
                }
                if item.hasSuffix(".framework") {
                    let frameName = item.components(separatedBy: "/").last?.components(separatedBy: ".framework").first ?? ""
                    if frameName != "" {
                        needDumpFilePaths.append(sourceUrl+"/"+item+"/"+frameName)
                        dumpedFilePaths.append(targetUrl+"/"+item+"/"+frameName)
                    }
                }
                if item.hasSuffix(".appex") {
                    let exName = item.components(separatedBy: "/").last?.components(separatedBy: ".appex").first ?? ""
                    if exName != "" {
                        needDumpFilePaths.append(sourceUrl+"/"+item+"/"+exName)
                        dumpedFilePaths.append(targetUrl+"/"+item+"/"+exName)
                    }
                }
            }
        } else {
            consoleIO.writeMessage("File is empty.", to: .error)
            return
        }
        
        // 2. Bổ sung: Tìm Mach-O files qua thư mục _CodeSignature
        findMachOFilesViaCodeSignature(in: sourceUrl, needDumpFilePaths: &needDumpFilePaths, dumpedFilePaths: &dumpedFilePaths)
        
        // Xử lý dump tất cả các file đã tìm thấy
        for (i, sourcePath) in needDumpFilePaths.enumerated() {
            let targetPath = dumpedFilePaths[i]
            let handle = dlopen(sourcePath, RTLD_LAZY | RTLD_GLOBAL)
            Dump.mapFile(path: sourcePath, mutable: false) { base_size, base_descriptor, base_error, base_raw in
                if let base = base_raw {
                    Dump.mapFile(path: targetPath, mutable: true) { dupe_size, dupe_descriptor, dupe_error, dupe_raw in
                        if let dupe = dupe_raw {
                            if base_size == dupe_size {
                                let header = UnsafeMutableRawPointer(mutating: dupe).assumingMemoryBound(to: mach_header_64.self)
                                assert(header.pointee.magic == MH_MAGIC_64)
                                assert(header.pointee.cputype == CPU_TYPE_ARM64)
                                assert(header.pointee.cpusubtype == CPU_SUBTYPE_ARM64_ALL)
                                
                                guard var curCmd = UnsafeMutablePointer<load_command>(bitPattern: UInt(bitPattern: header)+UInt(MemoryLayout<mach_header_64>.size)) else {
                                    return
                                }
                                
                                var segCmd : UnsafeMutablePointer<load_command>!
                                for _: UInt32 in 0 ..< header.pointee.ncmds {
                                    segCmd = curCmd
                                    if segCmd.pointee.cmd == LC_ENCRYPTION_INFO_64 {
                                        let command = UnsafeMutableRawPointer(mutating: segCmd).assumingMemoryBound(to: encryption_info_command_64.self)
                                        let result = Dump.dump(descriptor: base_descriptor, dupe: dupe, info: command.pointee)
                                        if result.0 {
                                            command.pointee.cryptid = 0
                                            consoleIO.writeMessage("Dump \(sourcePath) Success")
                                        } else {
                                            consoleIO.writeMessage("Dump \(sourcePath) fail, because of \(result.1)")
                                        }
                                        break
                                    }
                                    curCmd = UnsafeMutableRawPointer(curCmd).advanced(by: Int(curCmd.pointee.cmdsize)).assumingMemoryBound(to: load_command.self)
                                }
                                munmap(base, base_size)
                                munmap(dupe, dupe_size)
                                DispatchQueue.main.async {
                                    NotificationCenter.default.post(name: NSNotification.Name("stop"), object: nil)
                                }
                            } else {
                                munmap(base, base_size)
                                munmap(dupe, dupe_size)
                                consoleIO.writeMessage("If the files are not of the same size, then they are not duplicates of each other, which is an error.", to: .error)
                            }
                        } else {
                            munmap(base, base_size)
                            consoleIO.writeMessage("Read \(targetPath) Fail with \(dupe_error)", to: .error)
                        }
                    }
                } else {
                    consoleIO.writeMessage("Read \(sourcePath) Fail with \(base_error)", to: .error)
                }
            }
            dlclose(handle)
        }
    }
    
    // MARK: - Phương pháp tìm kiếm mới bổ sung
    private func findMachOFilesViaCodeSignature(in directory: String, needDumpFilePaths: inout [String], dumpedFilePaths: inout [String]) {
        let fileManager = FileManager.default
        
        if let enumerator = fileManager.enumerator(atPath: directory) {
            while let item = enumerator.nextObject() as? String {
                if item.hasSuffix("_CodeSignature") {
                    let parentDir = (directory as NSString).appendingPathComponent(item).replacingOccurrences(of: "/_CodeSignature", with: "")
                    
                    do {
                        let contents = try fileManager.contentsOfDirectory(atPath: parentDir)
                        
                        for file in contents {
                            let fullPath = (parentDir as NSString).appendingPathComponent(file)
                            var isDir: ObjCBool = false
                            
                            if fileManager.fileExists(atPath: fullPath, isDirectory: &isDir),
                               !isDir.boolValue,
                               isMachOFile(fullPath),
                               !needDumpFilePaths.contains(fullPath) {
                                
                                let relativePath = fullPath.replacingOccurrences(of: directory + "/", with: "")
                                let targetPath = (targetUrl as NSString).appendingPathComponent(relativePath)
                                
                                needDumpFilePaths.append(fullPath)
                                dumpedFilePaths.append(targetPath)
                                consoleIO.writeMessage("[+] Found additional Mach-O via _CodeSignature: \(fullPath)")
                            }
                        }
                    } catch {
                        consoleIO.writeMessage("Error processing \(parentDir): \(error)", to: .error)
                    }
                }
            }
        }
    }
    
    private func isMachOFile(_ path: String) -> Bool {
        guard let file = fopen(path, "r") else { return false }
        defer { fclose(file) }
        
        var magic: UInt32 = 0
        guard fread(&magic, 4, 1, file) == 1 else { return false }
        
        // Mach-O magic numbers (MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64)
        return magic == 0xfeedface || magic == 0xfeedfacf || 
               magic == 0xcefaedfe || magic == 0xcffaedfe
    }
    
    // MARK: - Các hàm gốc giữ nguyên
    static func dump(descriptor: Int32, dupe: UnsafeMutableRawPointer, info: encryption_info_command_64) -> (Bool, String) {
        let pageSize = Float(sysconf(_SC_PAGESIZE))
        let multiplier = ceil(Float(info.cryptoff) / pageSize)
        let alignedOffset = Int(multiplier * pageSize)

        let cryptsize = Int(info.cryptsize)
        let cryptoff = Int(info.cryptoff)
        let cryptid = Int(info.cryptid)
        
        let prot = PROT_READ | (cryptid == 0 ? 0 : PROT_EXEC)
        var base = mmap(nil, cryptsize, prot, MAP_PRIVATE, descriptor, off_t(alignedOffset))
        if base == MAP_FAILED {
            return (false, "mmap fail with \(String(cString: strerror(errno)))")
        }
        
        let error = mremap_encrypted(base!, cryptsize, info.cryptid, UInt32(CPU_TYPE_ARM64), UInt32(CPU_SUBTYPE_ARM64_ALL))
        if error != 0 {
            munmap(base, cryptsize)
            return (false, "encrypted fail with \(String(cString: strerror(errno)))")
        }

        if alignedOffset - cryptoff > cryptsize {
            posix_memalign(&base, cryptsize, cryptsize)
            memmove(dupe+UnsafeMutableRawPointer.Stride(info.cryptoff), base, cryptsize)
            free(base)
        } else {
            memmove(dupe+UnsafeMutableRawPointer.Stride(info.cryptoff), base, cryptsize)
            munmap(base, cryptsize)
        }
        return (true, "")
    }
    
    static func mapFile(path: UnsafePointer<CChar>, mutable: Bool, handle: (Int, Int32, String, UnsafeMutableRawPointer?)->()) {
        let f = open(path, mutable ? O_RDWR : O_RDONLY)
        if f < 0 {
            handle(0, 0, String(cString: strerror(errno)), nil)
            return
        }

        var s = stat()
        if fstat(f, &s) < 0 {
            close(f)
            handle(0, 0, String(cString: strerror(errno)), nil)
            return
        }

        let base = mmap(nil, Int(s.st_size), mutable ? (PROT_READ | PROT_WRITE) : PROT_READ, mutable ? MAP_SHARED : MAP_PRIVATE, f, 0)
        if base == MAP_FAILED {
            close(f)
            handle(0, 0, String(cString: strerror(errno)), nil)
            return
        }

        handle(Int(s.st_size), f, "", base)
    }
}
