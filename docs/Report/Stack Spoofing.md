หลังจากที่ได้ทำการ Bypass Userland hooking จาก EDR หรือ Endpoint Detection and Response ด้วยการค้นหาและใช้ SSN และยืมใช้ชุดคำสั่ง `syscall; ret` หรือภาษาในวงการที่เรียกว่า Gadget จากใน `ntdll.dll` เพื่อปลอมแปลงจุดการเรียกใช้ Native API ซึ่งเป็นเขตแดนสุดท้ายระหว่าง Ring 3 และ Ring 0 หรือที่เราเรียกเทคนิคนี้ว่า `Indirect Syscall` 

หากใครยังไม่ได้อ่าน `Indirect Syscall` สามารถอ่านได้ที่ [Indirect Syscall](Indirect%20Syscall.md)

ประเด็นคือ แม้ว่าเราจะสามารถข้ามการป้องกันในชั้น Ring 3 มาได้ แต่ในขณะเดียวกัน EDR และ Microsoft ก็ยังสามารถหาสารพัดวิธีมาป้องกัน Malware ได้ในชั้น Ring 0 หรือ Kernel Level ซึ่งวิธีการหลักที่ว่าคือการป้องกันด้วยสิ่งที่เรียกว่า `ETW-Ti` และ `Stack Walking` 

หากยังไม่ได้อ่านสามารถอ่านได้ที่ [__Main](__Main.md)

#### สรุปรวบรัดกลไกการป้องกันที่ `Indirect Syscall` ยังเอาชนะไม่ได้

#### 1. `ETW-Ti`
เมื่อ Kernel Callback เจอเข้ากับ Malware ที่สามารถซ่อนความผิดปกติของตัวเองได้ดีมาก เช่น **`Indirect Syscall`** ที่เราทำกันไป กลไกการตรวจสอบโดยที่ EDR จะเก็บ **`Log Event + Call Stack`** ของคำสั่งของ Process ที่มี Anomalies Behavior เช่น ถูกโหลดมาจากอินเตอร์เน็ต, ถูกส่งมาใน USB Flash drive, ถูกส่งเข้ามาผ่านทาง port network 

เมื่อเกิดคำสั่งที่น่าสงสัยขึ้น `ETW-Ti` Provider ที่เป็นตัวดักจับจะส่งข้อมูลดังกล่าวให้ `ETW-Ti` Session เพื่อผ่านมือส่งไปให้ EDR อีกที EDR ดังกล่าวมี ELAM หรือ Early Launch Anti-Malware Certificate ที่ออกให้โดย Microsoft ทำการตรวจสอบความผิดปกติของคำสั่งดังกล่าว โดยที่ Malware ไม่สามารถแก้ไขหรือดูระหว่างทางได้ สิ่งที่จะถูกตรวจสอบประกอบด้วย

1. Parameter Signature ตรวจจับหาตำแหน่งข้อมูลระดับ Byte ที่เรียงตัวแบบ Malware
2. `NtWriteVirtualMemory` หรือ `NtCreateThreadEx` ที่มีพฤติกรรมเขียนข้อมูลข้าม Process แบบผิดปกติ
3. `NtReadVirtualMemory` โดยเป้าหมายคือ `lsass.exe`
4. Unbacked Memory จากใน RAM หรือ Disk ที่ไม่มีไฟล์ถูกต้องตามระบบรองรับ

หากเข้าข่าย `ETW-Ti` ก็จะส่งข้อมูลไปให้ EDR จัดการตาม Rule ที่เขียนไว้ หรือ เจ้าหน้าที่ที่ดูแลทำการ Terminate Process นั้นทิ้งได้เลย

#### 2.`Stack Walking` 
