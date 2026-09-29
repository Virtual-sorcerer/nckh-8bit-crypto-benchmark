Source code firmware cho vi điều khiển 8-bit ATmega328P (Arduino Uno R3).

Đề tài: Đối sánh cấu trúc ARX (SPECK) và cấu trúc ma trận trạng thái (AES)
về hiệu năng và tài nguyên trên vi điều khiển 8-bit.

Nội dung:
  - uno_node.ino : firmware benchmark, chọn thuật toán bằng macro
                   (#define ALGO_AES / ALGO_SPECK / ALGO_ASCON)

Cách dùng:
  1. Mở Arduino IDE, mở file uno/uno_node.ino
  2. Comment/uncomment 1 trong 3 macro ở đầu file để chọn thuật toán
  3. Compile với board "Arduino Uno", flash lên board tương ứng
  4. Mở Serial Monitor 115200 baud, gửi:
     $INFO    -> in tên thuật toán
     $VERIFY  -> chạy 1 block, so với test vector chuẩn quốc tế
     $BENCH   -> chạy 1000 lần đo, in kết quả thời gian

Test vector đã được kiểm chứng trong firmware và đối chiếu với KAT NIST LWC.

Cấu hình thực nghiệm:
  - Vi điều khiển: ATmega328P @ 16 MHz
  - RAM: 2 KB SRAM, 32 KB Flash
  - Trình biên dịch: avr-gcc (Arduino IDE 2.x)
  - Tối ưu: -Os (mặc định)

Kết quả đo (trung bình 1000 lần, 100 block/lần):
  - AES-128:       697.76 µs/block  (11 164 chu kỳ, Flash 5 134 B)
  - SPECK-128/128: 752.57 µs/block  (12 041 chu kỳ, Flash 5 506 B)
  - ASCON-128:   3 846.92 µs/block  (61 551 chu kỳ, Flash 7 142 B)

Lỗi đã phát hiện và sửa (xem chi tiết trong file .ino):
  - BUG-1 (đã fix): ASCON sai domain separator và re-XOR key trước block 2.
    Test vector đúng: CT = BC820DBDF7A4631CD81CCC398E3E2BA0
