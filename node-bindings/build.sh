NAPI_URL=https://raw.githubusercontent.com/nodejs/node-addon-api/refs/heads/main
# Leave blank to dynamically link against hivemind (not recommended but maybe useful)
HIVEMIND_SRC=".."

INCLUDE="../include ../vqueue ../headers"
FLAGS="-Wno-vla -Wno-unused -Wno-deprecated -DNO_STDIO -DNDEBUG -flto -O3 -Wall -Wextra -Wno-unused -Wno-unused-parameter -Wno-unused-command-line-argument -march=native"
[ -n "${EXTRA_FLAGS+x}" ] || which lld >/dev/null 2>&1 && EXTRA_FLAGS="-fuse-ld=lld" # Flags that are ignored when not using clang

if [ -n "${TEST+x}" ]; then
	FLAGS="-Wno-vla -Wno-unused -Wno-deprecated -DNO_SOFT_ASSERT -DHIVEMIND_NO_LOCAL_BYPASS -DHIVEMIND_SIZED_FREE_VERIFY -g3 -fsanitize=address,undefined -Wall -Wextra -Werror -Wno-unused -Wno-unused-parameter -Wno-unused-command-line-argument"
elif [ -n "${PROFILE+x}" ]; then
	FLAGS="-Wno-vla -Wno-unused -Wno-deprecated -DNO_SOFT_ASSERT -DHIVEMIND_NO_LOCAL_BYPASS -Og -g3 -Wall -Wextra -Werror -Wno-unused -Wno-unused-parameter -Wno-unused-command-line-argument"
fi

printf "\e[4A\e[33;2m  *****************************\n ***                         ***\n***     \e[mBuilding \e[33;3mHivemind\e[33;2m     ***\n ***                         ***\n  *****************************\n\e[m\n"
cd "$(dirname $0)"
start="$(date +%s)"

fail(){
	printf '\e[91m      *** Build Failed! ***\e[m\r\n'
	[ -n "$1" ] && echo "$1"
	# Leave it for debugging
	# rm -rf dst
	exit 1
}

rm hivemind.node 2>/dev/null || true
mkdir dst 2>/dev/null; cd dst
alias exists="command -v $1 >/dev/null 2>&1"
printf "\e[90mDownloading <napi.h>\e[m\r\n"
if exists wget; then
	wget -q $NAPI_URL/napi.h $NAPI_URL/napi-inl.h $NAPI_URL/napi-inl.deprecated.h || fail "Failed to fetch napi.h"
else
	curl -s -O $NAPI_URL/napi.h -O $NAPI_URL/napi-inl.h -O $NAPI_URL/napi-inl.deprecated.h || fail "Failed to fetch napi.h"
fi
cd ..

printf "\e[90mDetecting compiler(s)\e[m\r\n"

exists "$CXX" || CXX=clang++
exists "$CXX" || { CXX=g++; EXTRA_FLAGS=; }
exists "$CXX" || fail "Could not find a C++ compiler"

INCLUDE="$(printf -- '-I%s ' $INCLUDE)"

[ -z "$HIVEMIND_SRC" ] && HIVEMIND_SRC="-lhivemind" || {
	exists "$CC" || CC=clang
	exists "$CC" || { CC=gcc; EXTRA_FLAGS=; }
	exists "$CC" || fail "Could not find a C compiler"
	printf "%s -O3 %s\r\n" "$CC" "$HIVEMIND_SRC/src/main.c"
	"$CC" -c $INCLUDE $HIVEMIND_SRC/src/main.c -std=c17 $FLAGS $EXTRA_FLAGS -fPIC -o dst/hivemind.o || fail
	HIVEMIND_SRC="dst/hivemind.o"
}
$CC -shared -latomic -o /dev/null >/dev/null 2>&1 && EXTRA_FLAGS="$EXTRA_FLAGS -latomic"

printf "%s -shared -O3 src/bindings.cc -lhivemind -o hivemind.node\r\n" "$CXX"
$CXX -Idst $INCLUDE -I$(dirname "$(command -v node)")/../include/node -std=c++20 $FLAGS $EXTRA_FLAGS -fno-exceptions -DNODE_ADDON_API_DISABLE_CPP_EXCEPTIONS -fPIC -shared src/bindings.cc $HIVEMIND_SRC -Wl,-undefined,dynamic_lookup -o hivemind.node || fail
[ -n "${KEEP_DST+x}" ] || rm -rf dst

printf '\n\e[92m  *** Build Succeeded in %ds ***\e[m\r\n' "$(($(date +%s) - start))"