# APK-Kong-CR-Generator

This project is used to generate Kong Gateway specific Custom Resources (CRs) when the APK configuration is provided.

## Prerequisites

- Go 1.23 or higher
- APK configuration files

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/terance-edmonds/apk-kong-cr-generator.git
    ```

2. Navigate to the project directory:

    ```sh
    cd apk-kong-cr-generator
    ```

3. Build the project:

    ```sh
    go build
    ```

## Usage

1. Ensure you have the necessary APK configuration files (Change main.go conf file path).
2. Run the tool:

    ```sh
    go run ./apk-kong-cr-generator/main.go
    ```

3. The generated Kong Gateway CRs will be output to the `./tmp` directory.