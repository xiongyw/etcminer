find_package(CUDA REQUIRED)

set(CUDA_NVCC_FLAGS ${CUDA_NVCC_FLAGS};--ptxas-options=-v;-use_fast_math;-lineinfo)

if (NOT MSVC)
	list(APPEND CUDA_NVCC_FLAGS "--disable-warnings")
endif()

list(APPEND CUDA_NVCC_FLAGS_RELEASE -O3)
list(APPEND CUDA_NVCC_FLAGS_DEBUG -G)

if(COMPUTE AND (COMPUTE GREATER 0))
	list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_${COMPUTE},code=sm_${COMPUTE}")
else()
	list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_50,code=sm_50")
	list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_52,code=sm_52")
	list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_53,code=sm_53")
	list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_60,code=sm_60")
	list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_61,code=sm_61")
	list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_62,code=sm_62")
	if(NOT CUDA_VERSION VERSION_LESS 9.0)
		list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_70,code=sm_70")
	endif()
	if(NOT CUDA_VERSION VERSION_LESS 10.0)
		list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_75,code=sm_75")
	endif()
	if(NOT CUDA_VERSION VERSION_LESS 11.0)
		# NVIDIA A100 and NVIDIA DGX-A100
		list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_80,code=sm_80")
	endif()
	if(NOT CUDA_VERSION VERSION_LESS 11.1)
		# Tesla GA10x cards, RTX Ampere �C RTX 3080/3090, RTX A6000, RTX A40
		list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_86,code=sm_86")
	endif()
endif()

file(GLOB sources "*.cpp" "*.cu")
file(GLOB headers "*.h" "*.cuh")

cuda_add_library(ethash-cuda STATIC ${sources} ${headers})
target_link_libraries(ethash-cuda ethcore ethash)
target_include_directories(ethash-cuda PUBLIC ${CUDA_INCLUDE_DIRS})
target_include_directories(ethash-cuda PRIVATE .. ${CMAKE_CURRENT_BINARY_DIR})
