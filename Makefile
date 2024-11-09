# Makefile to check and install yubico-piv-tool based on OS and YubiKey presence

# Commands to check yubico-piv-tool and YubiKey
CHECK_YUBICO_PIV_TOOL = which yubico-piv-tool
CHECK_YUBIKEY_LINUX = lsusb | grep -i 'Yubico'
CHECK_YUBIKEY_MAC = system_profiler SPUSBDataType | grep -i 'Yubico'
CHECK_YUBIKEY_WIN = powershell "Get-PnpDevice -FriendlyName '*Yubico*'"

# OS-specific installation commands
INSTALL_YUBICO_PIV_TOOL_LINUX = sudo apt-get install -y yubico-piv-tool
INSTALL_YUBICO_PIV_TOOL_MAC = brew install yubico-piv-tool
INSTALL_YUBICO_PIV_TOOL_WIN = choco install yubico-piv-tool -y

# Default target
build: check_yubico_piv_tool

check_yubico_piv_tool:
	@echo "Detecting Operating System..."
	@if [ "$(shell uname)" = "Linux" ]; then \
		echo "Linux detected."; \
		$(MAKE) check_yubikey_linux; \
		if ! $(CHECK_YUBICO_PIV_TOOL) > /dev/null 2>&1; then \
			echo "yubico-piv-tool is not installed. Installing..."; \
			$(INSTALL_YUBICO_PIV_TOOL_LINUX); \
		else \
			echo "yubico-piv-tool is already installed."; \
		fi \
	elif [ "$(shell uname)" = "Darwin" ]; then \
		echo "macOS detected."; \
		$(MAKE) check_yubikey_mac; \
		if ! $(CHECK_YUBICO_PIV_TOOL) > /dev/null 2>&1; then \
			echo "yubico-piv-tool is not installed. Installing..."; \
			$(INSTALL_YUBICO_PIV_TOOL_MAC); \
		else \
			echo "yubico-piv-tool is already installed."; \
		fi \
	elif [ "$(OS)" = "Windows_NT" ]; then \
		echo "Windows detected."; \
		$(MAKE) check_yubikey_win; \
		if ! $(CHECK_YUBICO_PIV_TOOL) > /dev/null 2>&1; then \
			echo "yubico-piv-tool is not installed. Installing..."; \
			$(INSTALL_YUBICO_PIV_TOOL_WIN); \
		else \
			echo "yubico-piv-tool is already installed."; \
		fi \
	else \
		echo "Unsupported OS."; \
	fi

check_yubikey_linux:
	@echo "Checking for YubiKey on Linux..."
	@if ! $(CHECK_YUBIKEY_LINUX) > /dev/null 2>&1; then \
		echo "No YubiKey detected. Please plug in your YubiKey and try again."; \
		exit 1; \
	else \
		echo "YubiKey detected."; \
	fi

check_yubikey_mac:
	@echo "Checking for YubiKey on macOS..."
	@if ! $(CHECK_YUBIKEY_MAC) > /dev/null 2>&1; then \
		echo "No YubiKey detected. Please plug in your YubiKey and try again."; \
		exit 1; \
	else \
		echo "YubiKey detected."; \
	fi

check_yubikey_win:
	@echo "Checking for YubiKey on Windows..."
	@if ! $(CHECK_YUBIKEY_WIN) > /dev/null 2>&1; then \
		echo "No YubiKey detected. Please plug in your YubiKey and try again."; \
		exit 1; \
	else \
		echo "YubiKey detected."; \
	fi
