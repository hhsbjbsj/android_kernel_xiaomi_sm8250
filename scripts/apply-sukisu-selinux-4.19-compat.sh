#!/usr/bin/env bash
set -euo pipefail

KSU_DIR="${1:?pass SukiSU source directory}"
SEPOLICY="$KSU_DIR/kernel/selinux/sepolicy.c"

[[ -f "$SEPOLICY" ]] || { echo "missing $SEPOLICY" >&2; exit 1; }
[[ "$(git -C "$KSU_DIR" describe --tags --exact-match HEAD 2>/dev/null || true)" == "v4.1.2" ]] || {
  echo "this compatibility patch only supports SukiSU v4.1.2" >&2
  exit 1
}

# Fail closed: this patch is only for the legacy Android/Linux 4.19 policydb
# representation used by this kernel tree.
ROOT="$(cd "$KSU_DIR/.." && pwd)"
grep -Fq 'struct flex_array *type_val_to_struct_array;' "$ROOT/security/selinux/ss/policydb.h"
grep -Fq 'struct flex_array *type_attr_map_array;' "$ROOT/security/selinux/ss/policydb.h"
grep -Fq 'struct filename_trans {' "$ROOT/security/selinux/ss/policydb.h"
grep -Fq 'struct hashtab *filename_trans;' "$ROOT/security/selinux/ss/policydb.h"

python3 - "$SEPOLICY" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

if '#include <linux/flex_array.h>' not in text:
    marker = '#include <linux/gfp.h>\n'
    if marker not in text:
        raise SystemExit('cannot locate gfp include in sepolicy.c')
    text = text.replace(marker, marker + '#include <linux/flex_array.h>\n', 1)


def find_definition(source: str, name: str):
    pat = re.compile(rf'(?m)^static\s+(?:bool|void)\s+{re.escape(name)}\s*\(')
    for m in pat.finditer(source):
        semi = source.find(';', m.end())
        brace = source.find('{', m.end())
        if brace < 0 or (semi >= 0 and semi < brace):
            continue
        depth = 0
        state = 'normal'
        i = brace
        while i < len(source):
            ch = source[i]
            nxt = source[i+1] if i + 1 < len(source) else ''
            if state == 'normal':
                if ch == '"': state = 'double'
                elif ch == "'": state = 'single'
                elif ch == '/' and nxt == '/': state = 'line'; i += 1
                elif ch == '/' and nxt == '*': state = 'block'; i += 1
                elif ch == '{': depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        while end < len(source) and source[end] in ' \t': end += 1
                        if end < len(source) and source[end] == '\n': end += 1
                        return m.start(), end
            elif state == 'double':
                if ch == '\\': i += 1
                elif ch == '"': state = 'normal'
            elif state == 'single':
                if ch == '\\': i += 1
                elif ch == "'": state = 'normal'
            elif state == 'line':
                if ch == '\n': state = 'normal'
            elif state == 'block':
                if ch == '*' and nxt == '/': state = 'normal'; i += 1
            i += 1
    raise SystemExit(f'function definition not found: {name}')


def replace_definition(source: str, name: str, replacement: str):
    start, end = find_definition(source, name)
    return source[:start] + replacement + source[end:]

# Linux >=5.9 helper block uses struct filename_trans_key and the newer
# hashtab API. It is dead on 4.19, but still fails compilation because the
# types are parsed. Remove only that guarded helper block.
helper_start = text.find('// 5.9.0 : static inline int hashtab_insert')
if helper_start >= 0:
    first_def, _ = find_definition(text, 'add_filename_trans')
    if first_def <= helper_start:
        raise SystemExit('unexpected filename transition helper layout')
    text = text[:helper_start] + text[first_def:]

legacy_filename = r'''static bool add_filename_trans(struct policydb *db, const char *s,
                               const char *t, const char *c, const char *d,
                               const char *o)
{
    struct type_datum *src, *tgt, *def;
    struct class_datum *cls;
    struct filename_trans key;
    struct filename_trans_datum *trans;
    struct filename_trans *new_key;

    src = symtab_search(&db->p_types, s);
    tgt = symtab_search(&db->p_types, t);
    cls = symtab_search(&db->p_classes, c);
    def = symtab_search(&db->p_types, d);
    if (!src || !tgt || !cls || !def)
        return false;

    key.stype = src->value;
    key.ttype = tgt->value;
    key.tclass = cls->value;
    key.name = o;

    trans = hashtab_search(db->filename_trans, &key);
    if (!trans) {
        trans = kzalloc(sizeof(*trans), GFP_ATOMIC);
        new_key = kzalloc(sizeof(*new_key), GFP_ATOMIC);
        if (!trans || !new_key) {
            kfree(trans);
            kfree(new_key);
            return false;
        }
        *new_key = key;
        new_key->name = kstrdup(key.name, GFP_ATOMIC);
        if (!new_key->name) {
            kfree(new_key);
            kfree(trans);
            return false;
        }
        trans->otype = def->value;
        if (hashtab_insert(db->filename_trans, new_key, trans)) {
            kfree((char *)new_key->name);
            kfree(new_key);
            kfree(trans);
            return false;
        }
    } else {
        trans->otype = def->value;
    }

    return ebitmap_set_bit(&db->filename_trans_ttypes, tgt->value - 1, 1) == 0;
}

'''
text = replace_definition(text, 'add_filename_trans', legacy_filename)

legacy_add_type = r'''static bool add_type(struct policydb *db, const char *type_name, bool attr)
{
    struct type_datum *type;
    struct flex_array *new_type_attr_map_array;
    struct flex_array *new_type_val_to_struct;
    struct flex_array *new_val_to_name_types;
    struct flex_array *old_fa;
    char *key;
    void *old_elem;
    u32 value;
    int i;

    type = symtab_search(&db->p_types, type_name);
    if (type)
        return true;

    value = ++db->p_types.nprim;
    type = kzalloc(sizeof(*type), GFP_ATOMIC);
    key = kstrdup(type_name, GFP_ATOMIC);
    if (!type || !key)
        return false;

    type->primary = 1;
    type->value = value;
    type->attribute = attr;
    if (symtab_insert(&db->p_types, key, type))
        return false;

    new_type_attr_map_array = flex_array_alloc(sizeof(struct ebitmap), value,
                                                GFP_ATOMIC | __GFP_ZERO);
    new_type_val_to_struct = flex_array_alloc(sizeof(struct type_datum *), value,
                                               GFP_ATOMIC | __GFP_ZERO);
    new_val_to_name_types = flex_array_alloc(sizeof(char *), value,
                                              GFP_ATOMIC | __GFP_ZERO);
    if (!new_type_attr_map_array || !new_type_val_to_struct || !new_val_to_name_types)
        return false;

    if (flex_array_prealloc(new_type_attr_map_array, 0, value,
                            GFP_ATOMIC | __GFP_ZERO) ||
        flex_array_prealloc(new_type_val_to_struct, 0, value,
                            GFP_ATOMIC | __GFP_ZERO) ||
        flex_array_prealloc(new_val_to_name_types, 0, value,
                            GFP_ATOMIC | __GFP_ZERO))
        return false;

    if (db->type_attr_map_array) {
        for (i = 0; i < db->type_attr_map_array->total_nr_elements; i++) {
            old_elem = flex_array_get(db->type_attr_map_array, i);
            if (old_elem)
                flex_array_put(new_type_attr_map_array, i, old_elem,
                               GFP_ATOMIC | __GFP_ZERO);
        }
    }
    if (db->type_val_to_struct_array) {
        for (i = 0; i < db->type_val_to_struct_array->total_nr_elements; i++) {
            old_elem = flex_array_get_ptr(db->type_val_to_struct_array, i);
            if (old_elem)
                flex_array_put_ptr(new_type_val_to_struct, i, old_elem,
                                   GFP_ATOMIC | __GFP_ZERO);
        }
    }
    if (db->sym_val_to_name[SYM_TYPES]) {
        for (i = 0; i < db->sym_val_to_name[SYM_TYPES]->total_nr_elements; i++) {
            old_elem = flex_array_get_ptr(db->sym_val_to_name[SYM_TYPES], i);
            if (old_elem)
                flex_array_put_ptr(new_val_to_name_types, i, old_elem,
                                   GFP_ATOMIC | __GFP_ZERO);
        }
    }

    old_fa = db->type_attr_map_array;
    db->type_attr_map_array = new_type_attr_map_array;
    if (old_fa)
        flex_array_free(old_fa);
    ebitmap_init(flex_array_get(db->type_attr_map_array, value - 1));
    ebitmap_set_bit(flex_array_get(db->type_attr_map_array, value - 1),
                    value - 1, 1);

    old_fa = db->type_val_to_struct_array;
    db->type_val_to_struct_array = new_type_val_to_struct;
    if (old_fa)
        flex_array_free(old_fa);
    flex_array_put_ptr(db->type_val_to_struct_array, value - 1, type,
                       GFP_ATOMIC | __GFP_ZERO);

    old_fa = db->sym_val_to_name[SYM_TYPES];
    db->sym_val_to_name[SYM_TYPES] = new_val_to_name_types;
    if (old_fa)
        flex_array_free(old_fa);
    flex_array_put_ptr(db->sym_val_to_name[SYM_TYPES], value - 1, key,
                       GFP_ATOMIC | __GFP_ZERO);

    for (i = 0; i < db->p_roles.nprim; i++)
        ebitmap_set_bit(&db->role_val_to_struct[i]->types, value - 1, 1);

    return true;
}

'''
text = replace_definition(text, 'add_type', legacy_add_type)

legacy_typeattr = r'''static void add_typeattribute_raw(struct policydb *db,
                                  struct type_datum *type,
                                  struct type_datum *attr)
{
    struct ebitmap *sattr;
    struct hashtab_node *node;
    struct constraint_node *n;
    struct constraint_expr *e;

    sattr = flex_array_get(db->type_attr_map_array, type->value - 1);
    if (!sattr)
        return;
    ebitmap_set_bit(sattr, attr->value - 1, 1);

    ksu_hashtab_for_each(db->p_classes.table, node)
    {
        struct class_datum *cls = (struct class_datum *)node->datum;
        for (n = cls->constraints; n; n = n->next) {
            for (e = n->expr; e; e = e->next) {
                if (e->expr_type == CEXPR_NAMES &&
                    ebitmap_get_bit(&e->type_names->types, attr->value - 1))
                    ebitmap_set_bit(&e->names, type->value - 1, 1);
            }
        }
    };
}

'''
text = replace_definition(text, 'add_typeattribute_raw', legacy_typeattr)

# Audit the exact incompatible fields/APIs that caused the CI failure.
for bad in (
    'struct filename_trans_key',
    'policydb_filenametr_search',
    'compat_filename_trans_count',
    'db->type_val_to_struct,',
    '&db->type_attr_map_array[',
):
    if bad in text:
        raise SystemExit(f'newer SELinux policydb reference remains: {bad}')

for good in (
    'struct filename_trans key;',
    'type_val_to_struct_array',
    'flex_array_get(db->type_attr_map_array',
):
    if good not in text:
        raise SystemExit(f'legacy SELinux compatibility marker missing: {good}')

path.write_text(text, encoding='utf-8')
PY

git -C "$KSU_DIR" diff --check -- kernel/selinux/sepolicy.c

echo "Applied Linux 4.19 legacy SELinux policydb compatibility to SukiSU v4.1.2"
