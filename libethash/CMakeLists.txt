if (NOT MSVC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wall -Wno-unknown-pragmas -Wextra -Wno-error=parentheses -pedantic")
endif()

set(FILES
	internal.c
	ethash.h
	endian.h
	compiler.h
	fnv.h
	data_sizes.h
	sha3.c
	sha3.h
)

add_library(ethash ${FILES})

