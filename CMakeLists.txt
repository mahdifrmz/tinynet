cmake_minimum_required(VERSION 3.18.3)

project(tinynet)

add_executable(${PROJECT_NAME}
    src/crc32.c
    src/main.c
    src/parser.c
    src/entity.c
    src/vm.c
)

target_link_libraries(${PROJECT_NAME} nl-3 nl-route-3)

add_definitions(-Wall -Werror)

target_include_directories(${PROJECT_NAME} PRIVATE toml)
target_include_directories(${PROJECT_NAME} PRIVATE /usr/include/libnl3)

install(TARGETS tinynet)        

add_custom_target(
    test
    COMMAND ./run-tests.sh $<TARGET_FILE:${PROJECT_NAME}>
    DEPENDS ${PROJECT_NAME}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test    
)
