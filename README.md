## Disclaimer: This project is for educational and security research purposes only. The author is not responsible for any misuse of this tool.
คำเตือน: โปรเจคนี้มีไว้เพื่อจุดประสงค์ทางการศึกษาและการวิจัยเท่านั้น ผู้เขียนไม่ขอรับผิดชอบในทุกกรณีหากมีการนำเนื้อหาไปใช้ในทางที่ผิด.

# Modern Windows Loader PoC Research

โครงการนี้เป็นโครงการวิจัยเชิงรุก (Offensive Security Research) ที่มุ่งเน้นการพัฒนา Loader บนระบบปฏิบัติการ Windows โดยใช้เทคนิค Evasion ขั้นสูง เพื่อศึกษาการทำงานของ Endpoint Detection and Response / Antivirus และกลไกการตรวจจับในระดับ Kernel-mode และ User-mode

โปรเจกต์นี้เขียนขึ้นด้วยภาษา **C++** และ **x64 Assembly** โดยเน้นความเข้าใจในระดับ Windows Internals โดยได้มีการ Implement เทคนิคที่ใช้ในการทำ Red Teaming และ Malware Development ระดับสากล ดังนี้ต่อไปนี้

- **Indirect Syscall** ใช้การทำ Dynamic SSN Resolution เพื่อหา System Service Numbers โดยตรงจาก Disk หรือ Memory หลบหลีกการดักจับแบบ Inline Hooking ของ EDR โดยการกระโดดไปยัง `syscall` instruction ภายใน `ntdll.dll` ดั้งเดิม
        
- **Module Stomping** เทคนิคการเขียนทับหน่วยความจำของ Legitimate Signed DLL ที่ถูกโหลดขึ้นมา เพื่อซ่อน Shellcode ไว้ในหน่วยความจำที่ดูน่าเชื่อถือ หลบการสแกนแบบ Private Memory
    
- **Stack Spoofing** เป็นการทำ Obfuscation เลียนแบบ Stack ที่ถูกกฎหมายให้กับ Call Stack เพื่อป้องกันการทำ **Stack-based Detection** ด้วยกระบวนการ ETW-Ti จาก EDR

---

## 🛠️ How to Build

- **Compiler** Visual Studio 2022 (v143)
    
- **Programming Language**
- ISO C++20
- Assembly
- LLVM (Clang-Cl)
    
- **Architecture** Windows x64

---

## 📖 In-depth Analysis & Documentation

รายละเอียดเชิงลึกเกี่ยวกับที่มาที่ไป, Logic การออกแบบ, ขั้นตอนการพัฒนา และผลการวิเคราะห์ผ่าน Debugger (x64dbg/WinDbg) สามารถอ่านต่อได้ที่รายงานฉบับสมบูรณ์:

🔗 [Read Full Technical Report]
