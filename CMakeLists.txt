cmake_minimum_required(VERSION 3.20)
project(weave VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBELF REQUIRED libelf)

# Генерация vmlinux.h
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
    COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
    COMMENT "Generating vmlinux.h"
)

# Компиляция BPF программы
set(BPF_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/mutex_probe.bpf.c)
set(BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/mutex_probe.bpf.o)
set(BPF_SKEL   ${CMAKE_CURRENT_BINARY_DIR}/mutex_probe.skel.h)

add_custom_command(
    OUTPUT ${BPF_OBJECT}
    COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_x86
        -I${CMAKE_CURRENT_BINARY_DIR}
        -I${CMAKE_CURRENT_SOURCE_DIR}/src/bpf
        -c ${BPF_SOURCE} -o ${BPF_OBJECT}
    DEPENDS ${BPF_SOURCE} ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
    COMMENT "Compiling BPF program"
)

add_custom_command(
    OUTPUT ${BPF_SKEL}
    COMMAND bpftool gen skeleton ${BPF_OBJECT} > ${BPF_SKEL}
    DEPENDS ${BPF_OBJECT}
    COMMENT "Generating BPF skeleton"
)

add_custom_target(bpf_skeleton DEPENDS ${BPF_SKEL})

# Основной исполняемый файл
add_executable(weave src/main.cpp
    src/collector/collector.cpp
    src/analyzer/dependency_graph.cpp   
    src/symbolizer/symbolizer.cpp )

add_dependencies(weave bpf_skeleton)

target_include_directories(weave PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBBPF_INCLUDE_DIRS}
)

target_link_libraries(weave PRIVATE
    ${LIBBPF_LIBRARIES}
    ${LIBELF_LIBRARIES}
    z
    pthread
)
# Unit tests
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(simple_mutex tests/fixtures/simple_mutex.cpp)
target_link_libraries(simple_mutex pthread)

add_executable(weave_tests
  "tests/unit/test_event.cpp"
 "tests/unit/test_spsc_queue.cpp" "tests/unit/test_histogram.cpp"
 "tests/unit/test_dependency_graph.cpp" "src/analyzer/dependency_graph.cpp" "src/symbolizer/symbolizer.cpp" "tests/unit/test_symbolizer.cpp")

target_include_directories(weave_tests PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(weave_tests PRIVATE
  GTest::gtest_main
  pthread
  ${LIBELF_LIBRARIES} 
)

include(GoogleTest)
gtest_discover_tests(weave_tests)
