# PolymoEngine

内部でElGamal暗号を使用して値を暗号化しています。よって、デバッグ対策に有効です。

**SUPPORTED POLYMORPHIC TYPES**
- _int8 (signed char)
- _uint8 (unsigned char)
- _int16 (short)
- _uint16 (unsigned short)
- _int32 (int)
- _uint32 (unsigned int)
- _int64 (long long)
- _uint64 (unsigned long long)
- String (std::string)

***バグがあったらプルリクとかイシューとか待ってます。***

## Example
```cpp
#include <cstdio>
#include "PolymoEngine.hpp"
using namespace Polymo;

int main() {
    InitPolymoEngine();

    _uint8 a = 0xF0;
    a += 0x0F;
    uint8_t b = a;
    printf("%d\n", b);

    return 0;
}
```

## 参考資料
- [Polymorphic-Engine](https://github.com/Nou4r/Polymorphic-Engine)

