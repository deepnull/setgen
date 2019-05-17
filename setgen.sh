#!/usr/bin/env bash

# check for trim4
command -v trimv4 || go get -v github.com/nexus166/trimv4 || exit 127;

biggest_lists() {
	find ${1:-.} -maxdepth 1 -type f -name "*.*set" -printf "%s,%p\n" | sort -nr | head -${2:-"50"} | cut -d',' -f2 | tr '\n' ' ';
}

find_lists() {
	find ${2:-.} -type f -name "*${1}*.*set" -printf "%p ";
}

sanitize_list() {
	sed -i '/^0/d' ${1} && printf "\\nRemoved lines/IPs starting with 0\\n";
}

# ensure we got the basic lists
FIREHOL_FOLDER=${1:-$(mktemp -d)}
FIREHOL_REPO="https://github.com/firehol/blocklist-ipsets"
cd "$FIREHOL_FOLDER";
printf "\\nFetching/Updating firehol lists..\\n";
git remote -v || (rm -fr *; git clone --progress "$FIREHOL_REPO" "$FIREHOL_FOLDER";);
git pull;
cd -;

## start collecting
ALL_LISTS="";

# fetch extras
trick77_TMP=$(mktemp)
if [[ ! -z "${FETCH_trick77}" ]]; then
	for extra_list in $(wget -qO- "https://raw.githubusercontent.com/trick77/ipset-blacklist/master/ipset-blacklist.conf" | grep -oE '\"http.*\"' | sed 's/"//g'); do
		wget -qO- "${extra_list}" >> "$trick77_TMP";
	done
else
	printf "\\nNot including github.com/trick77/ipset-blacklist lists\\n";
fi
ALL_LISTS+="${trick77_TMP} ";

# banning entire continents actually helps your CPUs. default to everything but EU.
BLOCKED_CONTINENTS=${BLOCKED_CONTINENTS:-"continent_af continent_as continent_na continent_oc continent_sa"}
for continent in ${BLOCKED_CONTINENTS}; do
        ALL_LISTS+=$(find_lists "$continent" ${FIREHOL_FOLDER});
done
printf "BLOCKED_CONTINENTS\\t%s\\n" "$BLOCKED_CONTINENTS";

# or just countries
BLOCKED_COUNTRIES=${BLOCKED_COUNTRIES:-"country_ru"}
for country in ${BLOCKED_COUNTRIES}; do
	ALL_LISTS+=$(find_lists "$country" ${FIREHOL_FOLDER});
done
printf "BLOCKED_COUNTRIES\\t%s\\n" "$BLOCKED_COUNTRIES";

# include top 50 lists from firehol
set -x;
ALL_LISTS+=$(biggest_lists ${FIREHOL_FOLDER} ${TOP_N_BIGGEST});
set +x;

# look for other lists we care about in the firehol folder
EXTRA_LISTS=${EXTRA_LISTS:-"tor_exits"}
for extra_set in ${EXTRA_LISTS}; do
	ALL_LISTS+=$(find_lists "$extra_set" ${FIREHOL_FOLDER});
done
printf "EXTRA\\t%s\\n" "$EXTRA_LISTS";

# done. start processing final output.
printf "\\nLists that will be considered:\\n%s\\n\\nStatus:\\t%s\\n" "${ALL_LISTS}" "$(cat $ALL_LISTS | wc -l)";

# compute final list
FINAL_LIST=$(mktemp)
printf "\\nRunning trimv4 against complete list.. ";
cat ${ALL_LISTS} | ${GOPATH}/bin/trimv4 - > "$FINAL_LIST" && printf "Done.\\n";

# sanitize it
sanitize_list "$FINAL_LIST"

# end of list processing
_count="$(wc -l $FINAL_LIST | awk '{print $1}')"
printf "\\nStatus: %s IPs/CIDRs\\n" "$_count"

# compute ipset maxelem needed
MAXELEM="$(printf "1"; for _i in $(seq 1 $(printf "$_count" | wc -m)); do printf "0"; done)"
[[ "$MAXELEM" -gt 1000000 ]] && (echo "List is too big.." && exit 128);

# create ipset restore file
printf "create blacklist-tmp -exist hash:net family inet maxelem %d\\ncreate blacklist -exist hash:net family inet maxelem %d\\n" "$MAXELEM" "$MAXELEM" > ./blacklist.restore
for _line in $(< ${FINAL_LIST}); do
	printf "add blacklist-tmp %s\\n" "${_line}" >> ./blacklist.restore;
done
printf "swap blacklist blacklist-tmp\\ndestroy blacklist-tmp\\n" >> ./blacklist.restore

printf "\\n%s is ready.\\n" "$(realpath blacklist.restore)"
mv -fv "$FINAL_LIST" "$(dirname blacklist.restore)/blacklist.txt"
echo "${ALL_LISTS}" | tr ' ' '\n' | sort > "$(dirname blacklist.restore)/blacklist.includes"

find $(dirname blacklist.restore) -name 'blacklist*'
