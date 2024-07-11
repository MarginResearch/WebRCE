MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))

check-depot-tools:
ifndef DEPOT_TOOLS
	echo 'Set path to depot_tools'
	exit 1
endif

install-pwntools:
	# install pwntools and binutils for aarch64
	python3 -m pip install --upgrade pip
	python3 -m pip install --upgrade pwntools
	/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
	echo 'export PATH="/opt/homebrew/opt/binutils/bin:$(PATH)"' >> ~/.zshrc

remove-android-debug:
	rm -rf ringrtc-debug
	sudo rm -rf Signal-Android-debug

remove-android-sdk-tools:
	rm -rf sdk

download-android-sdk-tools: remove-android-sdk-tools
	curl https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip \
		--output commandlinetools-linux-11076708_latest.zip
	unzip commandlinetools-linux-11076708_latest.zip
	mkdir sdk; mv cmdline-tools sdk
	cd sdk/cmdline-tools; mkdir latest; mv bin latest; mv lib latest; \
		mv NOTICE.txt latest; mv source.properties latest
	echo 'y' | ./sdk/cmdline-tools/latest/bin/sdkmanager \
		--install "ndk;25.1.8937393"
	find ./sdk -name "libunwind.a" | grep aarch64 -q || \
		echo "Error finding aarch64 libunwind.a, please check ndk install" && \
		exit 1

build-android-ringrtc-debug: check-depot-tools
ifeq (,$(wildcard $(shell pwd)/sdk))
	$(MAKE) download-android-sdk-tools
endif
	rm -rf ringrtc-debug
	sudo apt install libglib2.0-dev
	git clone https://github.com/signalapp/ringrtc.git ringrtc-debug
	# update version as of April 2024
	cd ringrtc-debug; git checkout v2.40.0; git apply ../ringrtc_android.diff
	cd ringrtc-debug; rustup target add \
		armv7-linux-androideabi aarch64-linux-android i686-linux-android \
		x86_64-linux-android
	cd ringrtc-debug && JOBS=32 \
	ANDROID_SDK_ROOT=$(PWD)/sdk/ \
		ANDROID_NDK_HOME=$(PWD)/sdk/ndk/25.1.8937393/ \
		PATH=$(DEPOT_TOOLS):$(PATH) make android
	file ./ringrtc-debug/out/android-arm64/debug/lib.unstripped/libringrtc_rffi.so | \
		grep "not stripped" -q || ( echo "Error, libringrtc_rffi.so is stripped" && \
		exit 1 )
	file ./ringrtc-debug/out/android-arm64/debug/lib.unstripped/libringrtc.so | \
		grep "not stripped" -q || ( echo "Error, libringrtc.so is stripped" && \
		exit 1 )

# Password for black server keychain is `password`
sign-android:
ifeq (,$(wildcard $(shell pwd)/my-release-key.keystore))
	keytool -genkey -v -keystore my-release-key.keystore -alias alias_name \
		-keyalg RSA -keysize 2048 -validity 10000
endif
ifeq (,$(wildcard $(shell pwd)/sdk))
	$(MAKE) download-android-sdk-tools
endif
	# update to 7.5.2 as of April 2024
	./sdk/build-tools/30.0.3/zipalign -p 4 \
		$(PWD)/Signal-Android-play-prod-arm64-v8a-debug-7.5.2.apk \
		$(PWD)/Signal-Android-play-prod-arm64-v8a-debug-7.5.2_unsigned_aligned.apk
	./sdk/build-tools/30.0.3/apksigner sign --ks-key-alias alias_name --ks \
		my-release-key.keystore --in \
		$(PWD)/Signal-Android-play-prod-arm64-v8a-debug-7.5.2_unsigned_aligned.apk \
		--out \
		$(PWD)/Signal-Android-play-prod-arm64-v8a-debug-7.5.2_signed_aligned.apk

build-android-debug:
ifeq (,$(wildcard $(shell pwd)/ringrtc-debug))
	$(MAKE) build-android-ringrtc-debug
endif
	sudo rm -rf Signal-Android-debug
	git clone https://github.com/signalapp/Signal-Android.git \
		--recurse-submodules Signal-Android-debug
	# update to 7.5.2 as of Apr 2024
	cd Signal-Android-debug; git checkout tags/v7.5.2
	cd Signal-Android-debug; git apply ../signal_android.diff
	cp $(PWD)/ringrtc-debug/out/android-arm64/debug/lib.unstripped/libringrtc.so \
		./Signal-Android-debug/app/src/main/jniLibs/arm64-v8a
	cp $(PWD)/ringrtc-debug/out/android-arm64/debug/lib.unstripped/libringrtc_rffi.so \
		./Signal-Android-debug/app/src/main/jniLibs/arm64-v8a
	cd Signal-Android-debug/reproducible-builds; docker build -t signal-android .
	cd Signal-Android-debug; docker run --rm -v $$(pwd):/project \
		-w /project signal-android \
		sh -c "git config --global --add safe.directory /project; ./gradlew clean assemblePlayProdDebug"
	cp Signal-Android-debug/app/build/outputs/apk/playProd/debug/Signal-Android-play-prod-arm64-v8a-debug-7.5.2.apk .
	$(MAKE) sign-android

remove-ios:
	rm -rf Signal-iOS-debug
	rm -rf Signal-iOS

rebuild-ringrtc: check-depot-tools
	cd Signal-iOS-debug/Pods/SignalRingRTC; make clean;
	cd Signal-iOS-debug/Pods/SignalRingRTC; \
		PATH=$(DEPOT_TOOLS):$(PATH) make ios
	cd Signal-iOS-debug/Pods/SignalRingRTC; \
		mv out/build/debug out/build/release; \
		mv out/debug out/release
	cd Signal-iOS-debug/Pods/SignalRingRTC; \
		cp out/release/libringrtc/aarch64-apple-ios-sim/libringrtc.a \
		out/release/libringrtc/

build-ios-debug: remove-ios check-depot-tools
	git clone https://github.com/signalapp/Signal-iOS.git \
	  --recurse-submodules Signal-iOS-debug
	# signal-ios version 7.13.0.131 as of Jun 2024
	cd Signal-iOS-debug; git checkout tags/7.13.0.131
	cd Signal-iOS-debug; make dependencies
	cd Signal-iOS-debug/Pods; rm -rf SignalRingRTC; \
		git clone https://github.com/signalapp/ringrtc.git SignalRingRTC
	# ringrtc v2.42.0 as of Jun 2024
	cd Signal-iOS-debug/Pods/SignalRingRTC; \
		git checkout tags/v2.42.0
	cd Signal-iOS-debug/Pods; git apply ../../pods_simulator.diff
	cd Signal-iOS-debug/Pods/SignalRingRTC && \
		git apply ../../../ringrtc_make.diff
	cd Signal-iOS-debug/Pods/SignalRingRTC/; \
		rustup target add aarch64-apple-ios x86_64-apple-ios \
			aarch64-apple-ios-sim && \
		rustup component add rustc && \
		rustup component add rust-src && \
		cargo install cbindgen;
	cd Signal-iOS-debug/Pods/SignalRingRTC; \
	  PATH=$(DEPOT_TOOLS):$(PATH) make ios
	cd Signal-iOS-debug/Pods/SignalRingRTC/src/webrtc/src && \
		git apply ../../../../../../webrtc.diff
	cd Signal-iOS-debug/Pods/SignalRingRTC; \
		PATH=$(DEPOT_TOOLS):$(PATH) make clean
	cd Signal-iOS-debug/Pods/SignalRingRTC; \
		PATH=$(DEPOT_TOOLS):$(PATH) make ios
	cd Signal-iOS-debug/Pods/SignalRingRTC; \
		mv out/build/aarch64-apple-ios-sim/debug \
			out/build/aarch64-apple-ios-sim/release; \
		mv out/build/debug out/build/release; \
		mv out/debug out/release
	cd Signal-iOS-debug/Pods/SignalRingRTC; \
		cp out/release/libringrtc/aarch64-apple-ios-sim/libringrtc.a \
		out/release/libringrtc/
