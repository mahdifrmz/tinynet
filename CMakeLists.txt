cmake_minimum_required(VERSION 3.22)

project(tomnet)

add_executable(${PROJECT_NAME}
    src/main.c
    toml/toml.c
)

target_link_libraries(${PROJECT_NAME} nl-3 nl-route-3)

add_definitions(-Wall -Werror)

target_include_directories(${PROJECT_NAME} PRIVATE toml)
target_include_directories(${PROJECT_NAME} PRIVATE /usr/include/libnl3)