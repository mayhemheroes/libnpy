# libnpy

libnpy is a simple C++ library for reading and writing of numpy's [.npy files](https://docs.scipy.org/doc/numpy/neps/npy-format.html).

Refer to [format.py](https://github.com/numpy/numpy/blob/master/numpy/lib/format.py) for a detailed description of the .npy format.

This libraries primary purpose is *writing* numerical data easily and efficiently into the .npy format.
It also allows *reading* .npy files, although only a very limited subset of data types are supported.

## Features
 - Writing C++ vectors (std::vector<T>) to .npy files
 - Reading (some) simple .npy files into C++ vectors

## Supported data types and mapping
 Only *scalar* *numeric* data types are supported. There is no natural way to represent more complex objects and parsing the header becomes tremendously more complex.
 Supported types:
 - unsigned integer
 - signed integer
 - floating point
 - complex floating point (std::complex<float>, ...)

## Usage

Reading data:
```c++
#include "npy.hpp"
#include <vector>

int main() {
  vector<unsigned long> shape;
  bool fortran_order;
  vector<double> data;
  
  const char * path = "data.npy";
  npy::LoadArrayFromNumpy(path, shape, fortran_order, data);
}

```

Writing data:
```c++
#include "npy.hpp"
#include <vector>
#include <array>

int main() {
  vector<unsigned long> shape;
  
  const char * path = "out.npy";

  const vector<double> data1 {1, 2, 3, 4, 5, 6};
  array<long unsigned, 2> leshape {{2,3}};
  npy::SaveArrayAsNumpy(path, false, leshape.size(), leshape.data(), data1);
}

```

See `test/` for examples.
C++11 is required. If you use g++, use `-std=c++11`.

## Known limitations
1. Only a few data types are supported.

2. The numpy header is a literal Python dictionary and the Python syntax is very permissive. libnpy's parser was only tested with numpy's implemenation of the .npy format.

## Contributing
Feel free to send me a pull request, open an issue, or contact me directly.

## License
The project is licensed under the [MIT](LICENSE) license
