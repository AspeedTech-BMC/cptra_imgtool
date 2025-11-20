# ASPEED CPTRA_IMGTOOL

ASPEED CPTRA image tool is to packages the SoC image into caliptra flash image layout.  This includes the caliptra-core and caliptra-mcu runtime images, the [Caliptra SoC Manifest](https://github.com/chipsalliance/caliptra-sw/tree/main/auth-manifest), prebuilt binaries and the bootloaders for the AST27xxA2 platform.

# Requirement
* Rustup for managing rust toolchain
    ``` bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
* Build caliptra-ss and caliptra-mcu-ss tool
    1. [Aspeed's caliptra-ss](https://github.com/AspeedTech-BMC/caliptra-sw)
        * Including Aspeed's proprietary feature like SVN version insert and prebuilt signature insert.
    2. [Official caliptra-mcu-ss](https://github.com/chipsalliance/caliptra-mcu-sw)
        * If you are developing on the AST27XXA2 platform, you must apply the fix from commit  2b7837402328ab611968d40243075082469df7ae.
    * Build command
        ``` bash
        cd cptra_imgtool

        git clone https://github.com/AspeedTech-BMC/caliptra-sw.git
        cd caliptra-ss
        cargo build -p caliptra-auth-manifest-app --target-dir ../target

        git clone https://github.com/chipsalliance/caliptra-mcu-sw.git
        cd caliptra-mcu-ss
        git reset --hard 2b7837402328ab611968d40243075082469df7ae
        cargo build -p xtask --target-dir ../target
        ```

# Build comand
* Build caliptra soc manifest
    ``` bash
    cargo run create-auth-man --prj ast2700-default
    ```
* Build caliptra flash image
    ``` bash
    cargo run create-auth-flash --prj ast2700-default
    ```

# Customer configuration
* Update the pre-build images in $MANIFEST_TOOL/prebuilt/$PROJECT/
    ```
    ├── prebuilt
    │   ├── ast2700a1-default
    │   │   ├── atf.bin
    │   │   ├── caliptra-fw.bin
    │   │   ├── ddr4_2d_pmu_train_dmem.bin
    │   │   ├── ddr4_2d_pmu_train_imem.bin
    │   │   ├── ddr4_pmu_train_dmem.bin
    │   │   ├── ddr4_pmu_train_imem.bin
    │   │   ├── ddr5_pmu_train_dmem.bin
    │   │   ├── ddr5_pmu_train_imem.bin
    │   │   ├── dp_fw.bin
    │   │   ├── optee.bin
    │   │   ├── ssp.bin
    │   │   ├── tsp.bin
    │   │   ├── u-boot.bin
    │   │   ├── u-boot-spl.bin
    │   │   ├── uefi_ast2700.bin
    │   │   ├── vnd_ecc_sig.der
    │   │   └── vnd_lms_sig.der
    ```
* Update customer key in $MANIFEST_TOOL/key/$PROJECT/
    ```
    ├── key
    │   ├── ast2700a1-default
    │   │   ├── own-fw-ecc-prvk.pem
    │   │   ├── own-fw-ecc-pubk.pem
    │   │   ├── own-fw-lms-prvk.pem
    │   │   ├── own-fw-lms-pubk.pem
    │   │   ├── own-man-ecc-prvk.pem
    │   │   ├── own-man-ecc-pubk.pem
    │   │   ├── own-man-lms-prvk.pem
    │   │   ├── own-man-lms-pubk.pem
    │   │   ├── vnd-fw-ecc-prvk.pem
    │   │   ├── vnd-fw-ecc-pubk.pem
    │   │   ├── vnd-fw-lms-prvk.pem
    │   │   ├── vnd-fw-lms-pubk.pem
    │   │   ├── vnd-man-ecc-prvk.pem
    │   │   ├── vnd-man-ecc-pubk.pem
    │   │   ├── vnd-man-lms-prvk.pem

    ```
