// Dump.swift
// appdump
//
// Created by paradiseduo on 2021/7/29.

import Foundation
import MachO

@_silgen_name("mremap_encrypted")
func mremap_encrypted(_: UnsafeMutableRawPointer, _: Int, _: UInt32, _: UInt32, _: UInt32) -> Int32

class Dump {
    let consoleIO = ConsoleIO()
    var targetUrl = ""
    
    // Hàm thực thi lệnh shell
    func shell(_ command: String) -> (String, String, Int32) {
        let task = Process()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        task.standardOutput = stdoutPipe
        task.standardError = stderrPipe
        task.arguments = ["-c", command]
        task.launchPath = "/bin/sh"
        task.launch()
        
        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        
        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""
        
        task.waitUntilExit()
        return (stdout, stderr, task.terminationStatus)
    }
    
    func staticMode() {
        // Kiểm tra đối số dòng lệnh
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
        
        // Thêm /Payload cho iOS
        #if os(iOS)
        if !targetUrl.hasSuffix("/Payload") {
            targetUrl += "/Payload"
        }
        #endif
        
        // Sao chép thư mục nguồn sang đích
        do {
            consoleIO.writeMessage("Sao chép từ \(sourceUrl) sang \(targetUrl)")
            var isDirectory: ObjCBool = false
            if fileManager.fileExists(atPath: targetUrl, isDirectory: &isDirectory) {
                if isDirectory.boolValue && !targetUrl.hasSuffix(".app") {
                    consoleIO.writeMessage("\(targetUrl) là thư mục", to: .error)
                } else {
                    try fileManager.removeItem(atPath: targetUrl)
                    consoleIO.writeMessage("Xóa \(targetUrl) thành công")
                }
            }
            try fileManager.copyItem(atPath: sourceUrl, toPath: targetUrl)
            consoleIO.writeMessage("Sao chép file thành công")
        } catch let e {
            consoleIO.writeMessage("Sao chép thất bại: \(e)", to: .error)
            return
        }
        
        var needDumpFilePaths = [String]()
        var dumpedFilePaths = [String]()
        
        // 1. Tìm Mach-O files qua extension
        let enumeratorAtPath = fileManager.enumerator(atPath: sourceUrl)
        if let arr = enumeratorAtPath?.allObjects as? [String] {
            for item in arr {
                if item.hasSuffix(".app") {
                    let machOName = item.components(separatedBy: "/").last?.components(separatedBy: ".app").first ?? ""
                    if machOName == "" {
                        consoleIO.writeMessage("Không tìm thấy tên Mach-O", to: .error)
                        continue
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
                                consoleIO.writeMessage("Ứng dụng không chạy trên Mac M1! Thêm --ignore-ios-check để tiếp tục", to: .error)
                                do { try fileManager.removeItem(atPath: targetUrl) } catch {}
                                exit(-10)
                            } else {
                                consoleIO.writeMessage("Cảnh báo: Ứng dụng không chạy trên Mac M1. Tiếp tục giải mã")
                            }
                        }
                    }
                    #endif
                    let sourcePath = sourceUrl+"/"+item+"/"+machOName
                    let targetPath = targetUrl+"/"+item+"/"+machOName
                    if !needDumpFilePaths.contains(sourcePath) && isMachOFile(sourcePath) {
                        needDumpFilePaths.append(sourcePath)
                        dumpedFilePaths.append(targetPath)
                        consoleIO.writeMessage("[+] Tìm thấy Mach-O qua .app: \(sourcePath)")
                    }
                }
                if item.hasSuffix(".framework") {
                    let frameName = item.components(separatedBy: "/").last?.components(separatedBy: ".framework").first ?? ""
                    if frameName != "" {
                        let sourcePath = sourceUrl+"/"+item+"/"+frameName
                        let targetPath = targetUrl+"/"+item+"/"+frameName
                        if !needDumpFilePaths.contains(sourcePath) && isMachOFile(sourcePath) {
                            needDumpFilePaths.append(sourcePath)
                            dumpedFilePaths.append(targetPath)
                            consoleIO.writeMessage("[+] Tìm thấy Mach-O qua .framework: \(sourcePath)")
                        }
                    }
                }
                if item.hasSuffix(".appex") {
                    let exName = item.components(separatedBy: "/").last?.components(separatedBy: ".appex").first ?? ""
                    if exName != "" {
                        let sourcePath = sourceUrl+"/"+item+"/"+exName
                        let targetPath = targetUrl+"/"+item+"/"+exName
                        if !needDumpFilePaths.contains(sourcePath) && isMachOFile(sourcePath) {
                            needDumpFilePaths.append(sourcePath)
                            dumpedFilePaths.append(targetPath)
                            consoleIO.writeMessage("[+] Tìm thấy Mach-O qua .appex: \(sourcePath)")
                        }
                    }
                }
            }
        } else {
            consoleIO.writeMessage("Thư mục nguồn rỗng", to: .error)
            return
        }
        
        // 2. Tìm Mach-O files qua _CodeSignature
        findMachOFilesViaCodeSignature(in: sourceUrl, needDumpFilePaths: &needDumpFilePaths, dumpedFilePaths: &dumpedFilePaths)
        
        // 3. Kiểm tra danh sách trước khi giải mã
        if needDumpFilePaths.isEmpty {
            consoleIO.writeMessage("Không tìm thấy file Mach-O để giải mã", to: .error)
            return
        }
        
        consoleIO.writeMessage("Tìm thấy \(needDumpFilePaths.count) file Mach-O để giải mã")
        
        // 4. Giải mã tất cả file Mach-O
        var successfulDumps = 0
        for (i, sourcePath) in needDumpFilePaths.enumerated() {
            let targetPath = dumpedFilePaths[i]
            consoleIO.writeMessage("Đang giải mã \(sourcePath) sang \(targetPath)")
            
            // Kiểm tra xem file có mã hóa không
            if !isEncryptedMachOFile(sourcePath) {
                consoleIO.writeMessage("File \(sourcePath) không được mã hóa, bỏ qua giải mã")
                successfulDumps += 1
                continue
            }
            
            let handle = dlopen(sourcePath, RTLD_LAZY | RTLD_GLOBAL)
            Dump.mapFile(path: sourcePath, mutable: false) { base_size, base_descriptor, base_error, base_raw in
                if let base = base_raw {
                    Dump.mapFile(path: targetPath, mutable: true) { dupe_size, dupe_descriptor, dupe_error, dupe_raw in
                        if let dupe = dupe_raw {
                            if base_size == dupe_size {
                                let header = UnsafeMutableRawPointer(mutating: dupe).assumingMemoryBound(to: mach_header_64.self)
                                guard header.pointee.magic == MH_MAGIC_64 || header.pointee.magic == MH_CIGAM_64 else {
                                    consoleIO.writeMessage("File \(sourcePath) không phải Mach-O 64-bit hợp lệ", to: .error)
                                    munmap(base, base_size)
                                    munmap(dupe, dupe_size)
                                    return
                                }
                                
                                guard var curCmd = UnsafeMutablePointer<load_command>(bitPattern: UInt(bitPattern: header)+UInt(MemoryLayout<mach_header_64>.size)) else {
                                    consoleIO.writeMessage("Không thể truy cập lệnh tải cho \(sourcePath)", to: .error)
                                    munmap(base, base_size)
                                    munmap(dupe, dupe_size)
                                    return
                                }
                                
                                var foundEncryptionInfo = false
                                for _ in 0 ..< header.pointee.ncmds {
                                    let segCmd = curCmd
                                    if segCmd.pointee.cmd == LC_ENCRYPTION_INFO_64 {
                                        let command = UnsafeMutableRawPointer(mutating: segCmd).assumingMemoryBound(to: encryption_info_command_64.self)
                                        let result = Dump.dump(descriptor: base_descriptor, dupe: dupe, info: command.pointee)
                                        if result.0 {
                                            command.pointee.cryptid = 0
                                            consoleIO.writeMessage("Giải mã \(sourcePath) thành công bằng mremap_encrypted")
                                            successfulDumps += 1
                                        } else {
                                            consoleIO.writeMessage("Giải mã \(sourcePath) thất bại: \(result.1)", to: .error)
                                        }
                                        foundEncryptionInfo = true
                                        break
                                    }
                                    curCmd = UnsafeMutableRawPointer(curCmd).advanced(by: Int(curCmd.pointee.cmdsize)).assumingMemoryBound(to: load_command.self)
                                }
                                if !foundEncryptionInfo {
                                    consoleIO.writeMessage("Không tìm thấy LC_ENCRYPTION_INFO_64 cho \(sourcePath)", to: .error)
                                }
                                munmap(base, base_size)
                                munmap(dupe, dupe_size)
                            } else {
                                consoleIO.writeMessage("Kích thước file nguồn và đích không khớp cho \(sourcePath)", to: .error)
                                munmap(base, base_size)
                                munmap(dupe, dupe_size)
                            }
                        } else {
                            consoleIO.writeMessage("Đọc \(targetPath) thất bại: \(dupe_error)", to: .error)
                            munmap(base, base_size)
                        }
                    }
                } else {
                    consoleIO.writeMessage("Đọc \(sourcePath) thất bại: \(base_error)", to: .error)
                }
            }
            dlclose(handle)
        }
        
        consoleIO.writeMessage("Quá trình giải mã hoàn tất: \(successfulDumps)/\(needDumpFilePaths.count) file được giải mã thành công")
    }
    
    // Tìm Mach-O files qua _CodeSignature
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
                                consoleIO.writeMessage("[+] Tìm thấy Mach-O qua _CodeSignature: \(fullPath)")
                            }
                        }
                    } catch {
                        consoleIO.writeMessage("Lỗi khi xử lý \(parentDir): \(error)", to: .error)
                    }
                }
            }
        }
    }
    
    // Kiểm tra file Mach-O hợp lệ
    private func isMachOFile(_ path: String) -> Bool {
        guard let file = fopen(path, "r") else {
            consoleIO.writeMessage("Không thể mở file \(path)", to: .error)
            return false
        }
        defer { fclose(file) }
        
        var header = mach_header_64()
        guard fread(&header, MemoryLayout<mach_header_64>.size, 1, file) == 1 else {
            consoleIO.writeMessage("Không thể đọc header Mach-O của \(path)", to: .error)
            return false
        }
        
        let validMagic = header.magic == MH_MAGIC_64 || header.magic == MH_CIGAM_64
        let validType = header.filetype == MH_EXECUTE || header.filetype == MH_DYLIB || header.filetype == MH_BUNDLE
        if !validMagic || !validType {
            consoleIO.writeMessage("File \(path) không phải Mach-O hợp lệ", to: .error)
            return false
        }
        return true
    }
    
    // Kiểm tra xem file Mach-O có mã hóa không
    private func isEncryptedMachOFile(_ path: String) -> Bool {
        guard let file = fopen(path, "r") else {
            consoleIO.writeMessage("Không thể mở file \(path)", to: .error)
            return false
        }
        defer { fclose(file) }
        
        var header = mach_header_64()
        guard fread(&header, MemoryLayout<mach_header_64>.size, 1, file) == 1 else {
            consoleIO.writeMessage("Không thể đọc header Mach-O của \(path)", to: .error)
            return false
        }
        
        guard header.magic == MH_MAGIC_64 || header.magic == MH_CIGAM_64 else {
            consoleIO.writeMessage("File \(path) không phải Mach-O 64-bit", to: .error)
            return false
        }
        
        var offset = MemoryLayout<mach_header_64>.size
        for _ in 0..<header.ncmds {
            var cmd = load_command()
            guard fseek(file, Int(offset), SEEK_SET) == 0,
                  fread(&cmd, MemoryLayout<load_command>.size, 1, file) == 1 else {
                consoleIO.writeMessage("Không thể đọc lệnh tải của \(path)", to: .error)
                return false
            }
            
            if cmd.cmd == LC_ENCRYPTION_INFO_64 {
                var encInfo = encryption_info_command_64()
                guard fseek(file, Int(offset), SEEK_SET) == 0,
                      fread(&encInfo, MemoryLayout<encryption_info_command_64>.size, 1, file) == 1 else {
                    consoleIO.writeMessage("Không thể đọc LC_ENCRYPTION_INFO_64 của \(path)", to: .error)
                    return false
                }
                return encInfo.cryptid != 0
            }
            offset += Int(cmd.cmdsize)
        }
        return false
    }
    
    // Giải mã Mach-O
    static func dump(descriptor: Int32, dupe: UnsafeMutableRawPointer, info: encryption_info_command_64) -> (Bool, String) {
        let pageSize = Float(sysconf(_SC_PAGESIZE))
        let multiplier = ceil(Float(info.cryptoff) / pageSize)
        let alignedOffset = Int(multiplier * pageSize)
        
        let cryptsize = Int(info.cryptsize)
        let cryptoff = Int(info.cryptoff)
        let cryptid = Int(info.cryptid)
        
        guard cryptid != 0 else {
            return (true, "File không được mã hóa, không cần giải mã")
        }
        
        let prot = PROT_READ | PROT_EXEC
        let base = mmap(nil, cryptsize, prot, MAP_PRIVATE, descriptor, off_t(alignedOffset))
        if base == MAP_FAILED {
            let error = String(cString: strerror(errno))
            return (false, "mmap thất bại: \(error)")
        }
        
        let errorCode = mremap_encrypted(base!, cryptsize, info.cryptid, UInt32(CPU_TYPE_ARM64), UInt32(CPU_SUBTYPE_ARM64_ALL))
        if errorCode != 0 {
            let error = String(cString: strerror(errno))
            munmap(base, cryptsize)
            return (false, "mremap_encrypted thất bại với mã lỗi \(errorCode): \(error)")
        }
        
        if alignedOffset - cryptoff > cryptsize {
            var alignedBase: UnsafeMutableRawPointer?
            posix_memalign(&alignedBase, cryptsize, cryptsize)
            if let alignedBase = alignedBase {
                memmove(dupe + UnsafeMutableRawPointer.Stride(info.cryptoff), base, cryptsize)
                free(alignedBase)
            } else {
                munmap(base, cryptsize)
                return (false, "posix_memalign thất bại")
            }
        } else {
            memmove(dupe + UnsafeMutableRawPointer.Stride(info.cryptoff), base, cryptsize)
        }
        munmap(base, cryptsize)
        return (true, "")
    }
    
    // Ánh xạ file vào bộ nhớ
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

// Định nghĩa class ConsoleIO chỉ một lần
class ConsoleIO {
    enum OutputType {
        case error
        case standard
    }
    
    func writeMessage(_ message: String, to: OutputType = .standard) {
        switch to {
        case .standard:
            print(message)
        case .error:
            fputs("\(message)\n", stderr)
        }
    }
    
    func printUsage() {
        let executableName = (CommandLine.arguments[0] as NSString).lastPathComponent
        writeMessage("Cách sử dụng: \(executableName) <đường_dẫn_nguồn> <đường_dẫn_đích> [--ignore-ios-check]")
        writeMessage("  <đường_dẫn_nguồn>: Đường dẫn đến thư mục ứng dụng nguồn")
        writeMessage("  <đường_dẫn_đích>: Đường dẫn đến thư mục đích cho file giải mã")
        writeMessage("  --ignore-ios-check: Bỏ qua kiểm tra chỉ dành cho iOS trên macOS")
    }
}

// Hàm main để gọi staticMode
@main
struct AppDumpMain {
    static func main() {
        let dump = Dump()
        dump.staticMode()
    }
}
