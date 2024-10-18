cmake_minimum_required(VERSION 3.22)

project(tomnet)

add_executable(${PROJECT_NAME}
    src/main.c
    toml/toml.c
)

add_definitions(-Wall -Werror)

target_include_directories(${PROJECT_NAME} PRIVATE toml)