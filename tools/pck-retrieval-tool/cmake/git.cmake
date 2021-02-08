cmake_minimum_required(VERSION 3.17)

include(FetchContent)

FetchContent_Declare(
  dcapCXX
  GIT_REPOSITORY https://hub.fastgit.org/intel/SGXDataCenterAttestationPrimitives.git
  GIT_TAG        DCAP_1.9
  GIT_PROGRESS   true
  SOURCE_DIR     ${dcapCxxDir}
  UPDATE_DISCONNECTED true
  CONFIGURE_COMMAND echo "skip configure for crates-apps"
  BUILD_COMMAND echo "skip build for crates-apps"
  INSTALL_COMMAND echo "skip install for crates-apps"
)

FetchContent_MakeAvailable(dcapCXX)
