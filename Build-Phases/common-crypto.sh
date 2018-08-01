COMMON_CRYPTO_DIR="${SDKROOT}/usr/include/CommonCrypto"
if [ -f "${COMMON_CRYPTO_DIR}/module.modulemap" ]
then
	echo "CommonCrypto already exists, skipping"
else
	# This if-statement means we'll only run the main script if the
	# CommonCrypto.framework directory doesn't exist because otherwise
	# the rest of the script causes a full recompile for anything
	# where CommonCrypto is a dependency
	# Do a "Clean Build Folder" to remove this directory and trigger
	# the rest of the script to run
	FRAMEWORK_DIR="${BUILT_PRODUCTS_DIR}/CommonCrypto.framework"

	if [ -d "${FRAMEWORK_DIR}" ]; then
	echo "${FRAMEWORK_DIR} already exists, so skipping the rest of the script."
	exit 0
	fi

	mkdir -p "${FRAMEWORK_DIR}/Modules"
	echo "module CommonCrypto [system] {
	    header \"${SDKROOT}/usr/include/CommonCrypto/CommonCrypto.h\"
	    export *
	}" >> "${FRAMEWORK_DIR}/Modules/module.modulemap"

	ln -sf "${SDKROOT}/usr/include/CommonCrypto" "${FRAMEWORK_DIR}/Headers"
fi
