NAPI_URL=https://raw.githubusercontent.com/nodejs/node-addon-api/refs/heads/main
HIVEMIND_INCLUDE="../include ../vqueue ../vqueue/include ../headers"
# Leave blank to dynamically link against hivemind (not recommended but maybe useful)
HIVEMIND_SRC="../src/main.c"

FLAGS="-Wno-vla -Wno-unused -Wno-deprecated -DNO_STDIO -DNDEBUG -flto -O3 -Wall -Wextra -Wno-unused -Wno-unused-parameter -Wno-unused-command-line-argument -march=native"
[ -n "${EXTRA_FLAGS+x}" ] || which lld >/dev/null 2>&1 && EXTRA_FLAGS="-fuse-ld=lld" # Flags that are ignored when not using clang

if [ -n "${TEST+x}" ]; then
	FLAGS="-Wno-vla -Wno-unused -Wno-deprecated -DNO_SOFT_ASSERT -DHIVEMIND_NO_LOCAL_BYPASS -g3 -fsanitize=address,undefined -Wall -Wextra -Werror -Wno-unused -Wno-unused-parameter -Wno-unused-command-line-argument"
elif [ -n "${PROFILE+x}" ]; then
	FLAGS="-Wno-vla -Wno-unused -Wno-deprecated -DNO_SOFT_ASSERT -DHIVEMIND_NO_LOCAL_BYPASS -g3 -Wall -Wextra -Werror -Wno-unused -Wno-unused-parameter -Wno-unused-command-line-argument"
fi

printf "\e[4A\e[33;2m  *****************************\n ***                         ***\n***     \e[mBuilding \e[33;3mHivemind\e[33;2m     ***\n ***                         ***\n  *****************************\n\e[m\n\n"
cd "$(dirname $0)"
start="$(date +%s)"

fail(){
	printf '\e[A\e[2K\e[91m      *** Build Failed! ***\e[m\r\n'
	[ -n "$1" ] && echo "$1"
	# Leave it for debugging
	# rm -rf dst
	exit 1
}

rm hivemind.node 2>/dev/null || true
mkdir dst 2>/dev/null; cd dst
alias exists="command -v $1 >/dev/null 2>&1"
printf "\e[A\e[2KDownloading <napi.h>\r\n"
if exists wget; then
	wget -q $NAPI_URL/napi.h $NAPI_URL/napi-inl.h $NAPI_URL/napi-inl.deprecated.h || fail "Failed to fetch napi.h"
else
	curl -s -O $NAPI_URL/napi.h -O $NAPI_URL/napi-inl.h -O $NAPI_URL/napi-inl.deprecated.h || fail "Failed to fetch napi.h"
fi
cd ..

printf "\e[A\e[2KDetecting compiler(s)\r\n"

exists "$CXX" || CXX=clang++
exists "$CXX" || { CXX=g++; EXTRA_FLAGS=; }
exists "$CXX" || fail "Could not find a C++ compiler"

HIVEMIND_INCLUDE="$(printf -- '-I%s ' $HIVEMIND_INCLUDE)"

[ -z "$HIVEMIND_SRC" ] && HIVEMIND_SRC="-lhivemind" || {
	exists "$CC" || CC=clang
	exists "$CC" || { CC=gcc; EXTRA_FLAGS=; }
	exists "$CC" || fail "Could not find a C compiler"
	printf "\e[A\e[2K%s -O3 %s\r\n" "$CC" "$HIVEMIND_SRC"
	"$CC" -c $HIVEMIND_INCLUDE $HIVEMIND_SRC -std=c17 $FLAGS $EXTRA_FLAGS -fPIC -o dst/hivemind.o || fail
	HIVEMIND_SRC="dst/hivemind.o"
}
[ clang -shared -latomic -o /dev/null ] && EXTRA_FLAGS="$EXTRA_FLAGS -latomic"

printf "\e[A\e[2K%s -shared -O3 src/bindings.cc -lhivemind -o hivemind.node\r\n" "$CXX"
$CXX -Idst $HIVEMIND_INCLUDE -I$(dirname "$(command -v node)")/../include/node -std=c++20 $FLAGS $EXTRA_FLAGS -fno-exceptions -DNODE_ADDON_API_DISABLE_CPP_EXCEPTIONS -fPIC -shared src/bindings.cc $HIVEMIND_SRC -Wl,-undefined,dynamic_lookup -o hivemind.node || fail
[ -n "${KEEP_DST+x}" ] || rm -rf dst

printf '\e[A\e[2K\e[92m  *** Build Succeeded in %ds ***\e[m\r\n' "$(($(date +%s) - start))"