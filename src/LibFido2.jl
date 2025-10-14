module LibFido2

using libfido2_jll
export libfido2_jll

using CEnum: CEnum, @cenum

struct __sigset_t
    __val::NTuple{16, Culong}
end

const sigset_t = __sigset_t

function fido_strerr(arg1)
    ccall((:fido_strerr, libfido2), Ptr{Cchar}, (Cint,), arg1)
end

mutable struct fido_dev end

# typedef void * fido_dev_io_open_t ( const char * )
const fido_dev_io_open_t = Cvoid

# typedef void fido_dev_io_close_t ( void * )
const fido_dev_io_close_t = Cvoid

# typedef int fido_dev_io_read_t ( void * , unsigned char * , size_t , int )
const fido_dev_io_read_t = Cvoid

# typedef int fido_dev_io_write_t ( void * , const unsigned char * , size_t )
const fido_dev_io_write_t = Cvoid

# typedef int fido_dev_rx_t ( struct fido_dev * , uint8_t , unsigned char * , size_t , int )
const fido_dev_rx_t = Cvoid

# typedef int fido_dev_tx_t ( struct fido_dev * , uint8_t , const unsigned char * , size_t )
const fido_dev_tx_t = Cvoid

struct fido_dev_io
    open::Ptr{fido_dev_io_open_t}
    close::Ptr{fido_dev_io_close_t}
    read::Ptr{fido_dev_io_read_t}
    write::Ptr{fido_dev_io_write_t}
end

const fido_dev_io_t = fido_dev_io

struct fido_dev_transport
    rx::Ptr{fido_dev_rx_t}
    tx::Ptr{fido_dev_tx_t}
end

const fido_dev_transport_t = fido_dev_transport

@cenum fido_opt_t::UInt32 begin
    FIDO_OPT_OMIT = 0
    FIDO_OPT_FALSE = 1
    FIDO_OPT_TRUE = 2
end

# typedef void fido_log_handler_t ( const char * )
const fido_log_handler_t = Cvoid

const fido_sigset_t = sigset_t

mutable struct fido_assert end

const fido_assert_t = fido_assert

mutable struct fido_cbor_info end

const fido_cbor_info_t = fido_cbor_info

mutable struct fido_cred end

const fido_cred_t = fido_cred

const fido_dev_t = fido_dev

mutable struct fido_dev_info end

const fido_dev_info_t = fido_dev_info

mutable struct es256_pk end

const es256_pk_t = es256_pk

mutable struct es256_sk end

const es256_sk_t = es256_sk

mutable struct es384_pk end

const es384_pk_t = es384_pk

mutable struct rs256_pk end

const rs256_pk_t = rs256_pk

mutable struct eddsa_pk end

const eddsa_pk_t = eddsa_pk

function fido_assert_new()
    ccall((:fido_assert_new, libfido2), Ptr{fido_assert_t}, ())
end

function fido_cred_new()
    ccall((:fido_cred_new, libfido2), Ptr{fido_cred_t}, ())
end

function fido_dev_new()
    ccall((:fido_dev_new, libfido2), Ptr{fido_dev_t}, ())
end

function fido_dev_new_with_info(arg1)
    ccall((:fido_dev_new_with_info, libfido2), Ptr{fido_dev_t}, (Ptr{fido_dev_info_t},), arg1)
end

function fido_dev_info_new(arg1)
    ccall((:fido_dev_info_new, libfido2), Ptr{fido_dev_info_t}, (Csize_t,), arg1)
end

function fido_cbor_info_new()
    ccall((:fido_cbor_info_new, libfido2), Ptr{fido_cbor_info_t}, ())
end

function fido_dev_io_handle(arg1)
    ccall((:fido_dev_io_handle, libfido2), Ptr{Cvoid}, (Ptr{fido_dev_t},), arg1)
end

function fido_assert_free(arg1)
    ccall((:fido_assert_free, libfido2), Cvoid, (Ptr{Ptr{fido_assert_t}},), arg1)
end

function fido_cbor_info_free(arg1)
    ccall((:fido_cbor_info_free, libfido2), Cvoid, (Ptr{Ptr{fido_cbor_info_t}},), arg1)
end

function fido_cred_free(arg1)
    ccall((:fido_cred_free, libfido2), Cvoid, (Ptr{Ptr{fido_cred_t}},), arg1)
end

function fido_dev_force_fido2(arg1)
    ccall((:fido_dev_force_fido2, libfido2), Cvoid, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_force_u2f(arg1)
    ccall((:fido_dev_force_u2f, libfido2), Cvoid, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_free(arg1)
    ccall((:fido_dev_free, libfido2), Cvoid, (Ptr{Ptr{fido_dev_t}},), arg1)
end

function fido_dev_info_free(arg1, arg2)
    ccall((:fido_dev_info_free, libfido2), Cvoid, (Ptr{Ptr{fido_dev_info_t}}, Csize_t), arg1, arg2)
end

function fido_init(arg1)
    ccall((:fido_init, libfido2), Cvoid, (Cint,), arg1)
end

function fido_set_log_handler(arg1)
    ccall((:fido_set_log_handler, libfido2), Cvoid, (Ptr{fido_log_handler_t},), arg1)
end

function fido_assert_authdata_ptr(arg1, arg2)
    ccall((:fido_assert_authdata_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_authdata_raw_ptr(arg1, arg2)
    ccall((:fido_assert_authdata_raw_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_clientdata_hash_ptr(arg1)
    ccall((:fido_assert_clientdata_hash_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_assert_t},), arg1)
end

function fido_assert_hmac_secret_ptr(arg1, arg2)
    ccall((:fido_assert_hmac_secret_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_id_ptr(arg1, arg2)
    ccall((:fido_assert_id_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_largeblob_key_ptr(arg1, arg2)
    ccall((:fido_assert_largeblob_key_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_sig_ptr(arg1, arg2)
    ccall((:fido_assert_sig_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_user_id_ptr(arg1, arg2)
    ccall((:fido_assert_user_id_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_blob_ptr(arg1, arg2)
    ccall((:fido_assert_blob_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_cbor_info_certs_name_ptr(arg1)
    ccall((:fido_cbor_info_certs_name_ptr, libfido2), Ptr{Ptr{Cchar}}, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_extensions_ptr(arg1)
    ccall((:fido_cbor_info_extensions_ptr, libfido2), Ptr{Ptr{Cchar}}, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_options_name_ptr(arg1)
    ccall((:fido_cbor_info_options_name_ptr, libfido2), Ptr{Ptr{Cchar}}, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_transports_ptr(arg1)
    ccall((:fido_cbor_info_transports_ptr, libfido2), Ptr{Ptr{Cchar}}, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_versions_ptr(arg1)
    ccall((:fido_cbor_info_versions_ptr, libfido2), Ptr{Ptr{Cchar}}, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_options_value_ptr(arg1)
    ccall((:fido_cbor_info_options_value_ptr, libfido2), Ptr{Bool}, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_assert_rp_id(arg1)
    ccall((:fido_assert_rp_id, libfido2), Ptr{Cchar}, (Ptr{fido_assert_t},), arg1)
end

function fido_assert_user_display_name(arg1, arg2)
    ccall((:fido_assert_user_display_name, libfido2), Ptr{Cchar}, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_user_icon(arg1, arg2)
    ccall((:fido_assert_user_icon, libfido2), Ptr{Cchar}, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_user_name(arg1, arg2)
    ccall((:fido_assert_user_name, libfido2), Ptr{Cchar}, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_cbor_info_algorithm_type(arg1, arg2)
    ccall((:fido_cbor_info_algorithm_type, libfido2), Ptr{Cchar}, (Ptr{fido_cbor_info_t}, Csize_t), arg1, arg2)
end

function fido_cred_display_name(arg1)
    ccall((:fido_cred_display_name, libfido2), Ptr{Cchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_fmt(arg1)
    ccall((:fido_cred_fmt, libfido2), Ptr{Cchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_rp_id(arg1)
    ccall((:fido_cred_rp_id, libfido2), Ptr{Cchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_rp_name(arg1)
    ccall((:fido_cred_rp_name, libfido2), Ptr{Cchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_user_name(arg1)
    ccall((:fido_cred_user_name, libfido2), Ptr{Cchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_dev_info_manufacturer_string(arg1)
    ccall((:fido_dev_info_manufacturer_string, libfido2), Ptr{Cchar}, (Ptr{fido_dev_info_t},), arg1)
end

function fido_dev_info_path(arg1)
    ccall((:fido_dev_info_path, libfido2), Ptr{Cchar}, (Ptr{fido_dev_info_t},), arg1)
end

function fido_dev_info_product_string(arg1)
    ccall((:fido_dev_info_product_string, libfido2), Ptr{Cchar}, (Ptr{fido_dev_info_t},), arg1)
end

function fido_dev_info_ptr(arg1, arg2)
    ccall((:fido_dev_info_ptr, libfido2), Ptr{fido_dev_info_t}, (Ptr{fido_dev_info_t}, Csize_t), arg1, arg2)
end

function fido_cbor_info_protocols_ptr(arg1)
    ccall((:fido_cbor_info_protocols_ptr, libfido2), Ptr{UInt8}, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_certs_value_ptr(arg1)
    ccall((:fido_cbor_info_certs_value_ptr, libfido2), Ptr{UInt64}, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_aaguid_ptr(arg1)
    ccall((:fido_cbor_info_aaguid_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cred_aaguid_ptr(arg1)
    ccall((:fido_cred_aaguid_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_attstmt_ptr(arg1)
    ccall((:fido_cred_attstmt_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_authdata_ptr(arg1)
    ccall((:fido_cred_authdata_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_authdata_raw_ptr(arg1)
    ccall((:fido_cred_authdata_raw_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_clientdata_hash_ptr(arg1)
    ccall((:fido_cred_clientdata_hash_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_id_ptr(arg1)
    ccall((:fido_cred_id_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_largeblob_key_ptr(arg1)
    ccall((:fido_cred_largeblob_key_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_pubkey_ptr(arg1)
    ccall((:fido_cred_pubkey_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_sig_ptr(arg1)
    ccall((:fido_cred_sig_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_user_id_ptr(arg1)
    ccall((:fido_cred_user_id_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_x5c_ptr(arg1)
    ccall((:fido_cred_x5c_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_x5c_list_ptr(arg1, arg2)
    ccall((:fido_cred_x5c_list_ptr, libfido2), Ptr{Cuchar}, (Ptr{fido_cred_t}, Csize_t), arg1, arg2)
end

function fido_assert_allow_cred(arg1, arg2, arg3)
    ccall((:fido_assert_allow_cred, libfido2), Cint, (Ptr{fido_assert_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_assert_empty_allow_list(arg1)
    ccall((:fido_assert_empty_allow_list, libfido2), Cint, (Ptr{fido_assert_t},), arg1)
end

function fido_assert_set_authdata(arg1, arg2, arg3, arg4)
    ccall((:fido_assert_set_authdata, libfido2), Cint, (Ptr{fido_assert_t}, Csize_t, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3, arg4)
end

function fido_assert_set_authdata_raw(arg1, arg2, arg3, arg4)
    ccall((:fido_assert_set_authdata_raw, libfido2), Cint, (Ptr{fido_assert_t}, Csize_t, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3, arg4)
end

function fido_assert_set_clientdata(arg1, arg2, arg3)
    ccall((:fido_assert_set_clientdata, libfido2), Cint, (Ptr{fido_assert_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_assert_set_clientdata_hash(arg1, arg2, arg3)
    ccall((:fido_assert_set_clientdata_hash, libfido2), Cint, (Ptr{fido_assert_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_assert_set_count(arg1, arg2)
    ccall((:fido_assert_set_count, libfido2), Cint, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_set_extensions(arg1, arg2)
    ccall((:fido_assert_set_extensions, libfido2), Cint, (Ptr{fido_assert_t}, Cint), arg1, arg2)
end

function fido_assert_set_hmac_salt(arg1, arg2, arg3)
    ccall((:fido_assert_set_hmac_salt, libfido2), Cint, (Ptr{fido_assert_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_assert_set_hmac_secret(arg1, arg2, arg3, arg4)
    ccall((:fido_assert_set_hmac_secret, libfido2), Cint, (Ptr{fido_assert_t}, Csize_t, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3, arg4)
end

function fido_assert_set_options(arg1, arg2, arg3)
    ccall((:fido_assert_set_options, libfido2), Cint, (Ptr{fido_assert_t}, Bool, Bool), arg1, arg2, arg3)
end

function fido_assert_set_rp(arg1, arg2)
    ccall((:fido_assert_set_rp, libfido2), Cint, (Ptr{fido_assert_t}, Ptr{Cchar}), arg1, arg2)
end

function fido_assert_set_up(arg1, arg2)
    ccall((:fido_assert_set_up, libfido2), Cint, (Ptr{fido_assert_t}, fido_opt_t), arg1, arg2)
end

function fido_assert_set_uv(arg1, arg2)
    ccall((:fido_assert_set_uv, libfido2), Cint, (Ptr{fido_assert_t}, fido_opt_t), arg1, arg2)
end

function fido_assert_set_sig(arg1, arg2, arg3, arg4)
    ccall((:fido_assert_set_sig, libfido2), Cint, (Ptr{fido_assert_t}, Csize_t, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3, arg4)
end

function fido_assert_set_winhello_appid(arg1, arg2)
    ccall((:fido_assert_set_winhello_appid, libfido2), Cint, (Ptr{fido_assert_t}, Ptr{Cchar}), arg1, arg2)
end

function fido_assert_verify(arg1, arg2, arg3, arg4)
    ccall((:fido_assert_verify, libfido2), Cint, (Ptr{fido_assert_t}, Csize_t, Cint, Ptr{Cvoid}), arg1, arg2, arg3, arg4)
end

function fido_cbor_info_algorithm_cose(arg1, arg2)
    ccall((:fido_cbor_info_algorithm_cose, libfido2), Cint, (Ptr{fido_cbor_info_t}, Csize_t), arg1, arg2)
end

function fido_cred_empty_exclude_list(arg1)
    ccall((:fido_cred_empty_exclude_list, libfido2), Cint, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_entattest(arg1)
    ccall((:fido_cred_entattest, libfido2), Bool, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_exclude(arg1, arg2, arg3)
    ccall((:fido_cred_exclude, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_cred_prot(arg1)
    ccall((:fido_cred_prot, libfido2), Cint, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_set_attstmt(arg1, arg2, arg3)
    ccall((:fido_cred_set_attstmt, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_cred_set_attobj(arg1, arg2, arg3)
    ccall((:fido_cred_set_attobj, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_cred_set_authdata(arg1, arg2, arg3)
    ccall((:fido_cred_set_authdata, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_cred_set_authdata_raw(arg1, arg2, arg3)
    ccall((:fido_cred_set_authdata_raw, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_cred_set_blob(arg1, arg2, arg3)
    ccall((:fido_cred_set_blob, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_cred_set_clientdata(arg1, arg2, arg3)
    ccall((:fido_cred_set_clientdata, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_cred_set_clientdata_hash(arg1, arg2, arg3)
    ccall((:fido_cred_set_clientdata_hash, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_cred_set_entattest(arg1, arg2)
    ccall((:fido_cred_set_entattest, libfido2), Cint, (Ptr{fido_cred_t}, Cint), arg1, arg2)
end

function fido_cred_set_extensions(arg1, arg2)
    ccall((:fido_cred_set_extensions, libfido2), Cint, (Ptr{fido_cred_t}, Cint), arg1, arg2)
end

function fido_cred_set_fmt(arg1, arg2)
    ccall((:fido_cred_set_fmt, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cchar}), arg1, arg2)
end

function fido_cred_set_id(arg1, arg2, arg3)
    ccall((:fido_cred_set_id, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_cred_set_options(arg1, arg2, arg3)
    ccall((:fido_cred_set_options, libfido2), Cint, (Ptr{fido_cred_t}, Bool, Bool), arg1, arg2, arg3)
end

function fido_cred_set_pin_minlen(arg1, arg2)
    ccall((:fido_cred_set_pin_minlen, libfido2), Cint, (Ptr{fido_cred_t}, Csize_t), arg1, arg2)
end

function fido_cred_set_prot(arg1, arg2)
    ccall((:fido_cred_set_prot, libfido2), Cint, (Ptr{fido_cred_t}, Cint), arg1, arg2)
end

function fido_cred_set_rk(arg1, arg2)
    ccall((:fido_cred_set_rk, libfido2), Cint, (Ptr{fido_cred_t}, fido_opt_t), arg1, arg2)
end

function fido_cred_set_rp(arg1, arg2, arg3)
    ccall((:fido_cred_set_rp, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cchar}, Ptr{Cchar}), arg1, arg2, arg3)
end

function fido_cred_set_sig(arg1, arg2, arg3)
    ccall((:fido_cred_set_sig, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_cred_set_type(arg1, arg2)
    ccall((:fido_cred_set_type, libfido2), Cint, (Ptr{fido_cred_t}, Cint), arg1, arg2)
end

function fido_cred_set_uv(arg1, arg2)
    ccall((:fido_cred_set_uv, libfido2), Cint, (Ptr{fido_cred_t}, fido_opt_t), arg1, arg2)
end

function fido_cred_type(arg1)
    ccall((:fido_cred_type, libfido2), Cint, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_set_user(arg1, arg2, arg3, arg4, arg5, arg6)
    ccall((:fido_cred_set_user, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cuchar}, Csize_t, Ptr{Cchar}, Ptr{Cchar}, Ptr{Cchar}), arg1, arg2, arg3, arg4, arg5, arg6)
end

function fido_cred_set_x509(arg1, arg2, arg3)
    ccall((:fido_cred_set_x509, libfido2), Cint, (Ptr{fido_cred_t}, Ptr{Cuchar}, Csize_t), arg1, arg2, arg3)
end

function fido_cred_verify(arg1)
    ccall((:fido_cred_verify, libfido2), Cint, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_verify_self(arg1)
    ccall((:fido_cred_verify_self, libfido2), Cint, (Ptr{fido_cred_t},), arg1)
end

function fido_dev_set_sigmask(arg1, arg2)
    ccall((:fido_dev_set_sigmask, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{fido_sigset_t}), arg1, arg2)
end

function fido_dev_cancel(arg1)
    ccall((:fido_dev_cancel, libfido2), Cint, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_close(arg1)
    ccall((:fido_dev_close, libfido2), Cint, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_get_assert(arg1, arg2, arg3)
    ccall((:fido_dev_get_assert, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{fido_assert_t}, Ptr{Cchar}), arg1, arg2, arg3)
end

function fido_dev_get_cbor_info(arg1, arg2)
    ccall((:fido_dev_get_cbor_info, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{fido_cbor_info_t}), arg1, arg2)
end

function fido_dev_get_retry_count(arg1, arg2)
    ccall((:fido_dev_get_retry_count, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{Cint}), arg1, arg2)
end

function fido_dev_get_uv_retry_count(arg1, arg2)
    ccall((:fido_dev_get_uv_retry_count, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{Cint}), arg1, arg2)
end

function fido_dev_get_touch_begin(arg1)
    ccall((:fido_dev_get_touch_begin, libfido2), Cint, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_get_touch_status(arg1, arg2, arg3)
    ccall((:fido_dev_get_touch_status, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{Cint}, Cint), arg1, arg2, arg3)
end

function fido_dev_info_manifest(arg1, arg2, arg3)
    ccall((:fido_dev_info_manifest, libfido2), Cint, (Ptr{fido_dev_info_t}, Csize_t, Ptr{Csize_t}), arg1, arg2, arg3)
end

function fido_dev_info_set(arg1, arg2, arg3, arg4, arg5, arg6, arg7)
    ccall((:fido_dev_info_set, libfido2), Cint, (Ptr{fido_dev_info_t}, Csize_t, Ptr{Cchar}, Ptr{Cchar}, Ptr{Cchar}, Ptr{fido_dev_io_t}, Ptr{fido_dev_transport_t}), arg1, arg2, arg3, arg4, arg5, arg6, arg7)
end

function fido_dev_make_cred(arg1, arg2, arg3)
    ccall((:fido_dev_make_cred, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{fido_cred_t}, Ptr{Cchar}), arg1, arg2, arg3)
end

function fido_dev_open_with_info(arg1)
    ccall((:fido_dev_open_with_info, libfido2), Cint, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_open(arg1, arg2)
    ccall((:fido_dev_open, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{Cchar}), arg1, arg2)
end

function fido_dev_reset(arg1)
    ccall((:fido_dev_reset, libfido2), Cint, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_set_io_functions(arg1, arg2)
    ccall((:fido_dev_set_io_functions, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{fido_dev_io_t}), arg1, arg2)
end

function fido_dev_set_pin(arg1, arg2, arg3)
    ccall((:fido_dev_set_pin, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{Cchar}, Ptr{Cchar}), arg1, arg2, arg3)
end

function fido_dev_set_transport_functions(arg1, arg2)
    ccall((:fido_dev_set_transport_functions, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{fido_dev_transport_t}), arg1, arg2)
end

function fido_dev_set_timeout(arg1, arg2)
    ccall((:fido_dev_set_timeout, libfido2), Cint, (Ptr{fido_dev_t}, Cint), arg1, arg2)
end

function fido_assert_authdata_len(arg1, arg2)
    ccall((:fido_assert_authdata_len, libfido2), Csize_t, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_authdata_raw_len(arg1, arg2)
    ccall((:fido_assert_authdata_raw_len, libfido2), Csize_t, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_clientdata_hash_len(arg1)
    ccall((:fido_assert_clientdata_hash_len, libfido2), Csize_t, (Ptr{fido_assert_t},), arg1)
end

function fido_assert_count(arg1)
    ccall((:fido_assert_count, libfido2), Csize_t, (Ptr{fido_assert_t},), arg1)
end

function fido_assert_hmac_secret_len(arg1, arg2)
    ccall((:fido_assert_hmac_secret_len, libfido2), Csize_t, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_id_len(arg1, arg2)
    ccall((:fido_assert_id_len, libfido2), Csize_t, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_largeblob_key_len(arg1, arg2)
    ccall((:fido_assert_largeblob_key_len, libfido2), Csize_t, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_sig_len(arg1, arg2)
    ccall((:fido_assert_sig_len, libfido2), Csize_t, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_user_id_len(arg1, arg2)
    ccall((:fido_assert_user_id_len, libfido2), Csize_t, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_blob_len(arg1, arg2)
    ccall((:fido_assert_blob_len, libfido2), Csize_t, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_cbor_info_aaguid_len(arg1)
    ccall((:fido_cbor_info_aaguid_len, libfido2), Csize_t, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_algorithm_count(arg1)
    ccall((:fido_cbor_info_algorithm_count, libfido2), Csize_t, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_certs_len(arg1)
    ccall((:fido_cbor_info_certs_len, libfido2), Csize_t, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_extensions_len(arg1)
    ccall((:fido_cbor_info_extensions_len, libfido2), Csize_t, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_options_len(arg1)
    ccall((:fido_cbor_info_options_len, libfido2), Csize_t, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_protocols_len(arg1)
    ccall((:fido_cbor_info_protocols_len, libfido2), Csize_t, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_transports_len(arg1)
    ccall((:fido_cbor_info_transports_len, libfido2), Csize_t, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_versions_len(arg1)
    ccall((:fido_cbor_info_versions_len, libfido2), Csize_t, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cred_aaguid_len(arg1)
    ccall((:fido_cred_aaguid_len, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_attstmt_len(arg1)
    ccall((:fido_cred_attstmt_len, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_authdata_len(arg1)
    ccall((:fido_cred_authdata_len, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_authdata_raw_len(arg1)
    ccall((:fido_cred_authdata_raw_len, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_clientdata_hash_len(arg1)
    ccall((:fido_cred_clientdata_hash_len, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_id_len(arg1)
    ccall((:fido_cred_id_len, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_largeblob_key_len(arg1)
    ccall((:fido_cred_largeblob_key_len, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_pin_minlen(arg1)
    ccall((:fido_cred_pin_minlen, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_pubkey_len(arg1)
    ccall((:fido_cred_pubkey_len, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_sig_len(arg1)
    ccall((:fido_cred_sig_len, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_user_id_len(arg1)
    ccall((:fido_cred_user_id_len, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_x5c_len(arg1)
    ccall((:fido_cred_x5c_len, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_x5c_list_count(arg1)
    ccall((:fido_cred_x5c_list_count, libfido2), Csize_t, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_x5c_list_len(arg1, arg2)
    ccall((:fido_cred_x5c_list_len, libfido2), Csize_t, (Ptr{fido_cred_t}, Csize_t), arg1, arg2)
end

function fido_assert_flags(arg1, arg2)
    ccall((:fido_assert_flags, libfido2), UInt8, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_assert_sigcount(arg1, arg2)
    ccall((:fido_assert_sigcount, libfido2), UInt32, (Ptr{fido_assert_t}, Csize_t), arg1, arg2)
end

function fido_cred_flags(arg1)
    ccall((:fido_cred_flags, libfido2), UInt8, (Ptr{fido_cred_t},), arg1)
end

function fido_cred_sigcount(arg1)
    ccall((:fido_cred_sigcount, libfido2), UInt32, (Ptr{fido_cred_t},), arg1)
end

function fido_dev_protocol(arg1)
    ccall((:fido_dev_protocol, libfido2), UInt8, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_major(arg1)
    ccall((:fido_dev_major, libfido2), UInt8, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_minor(arg1)
    ccall((:fido_dev_minor, libfido2), UInt8, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_build(arg1)
    ccall((:fido_dev_build, libfido2), UInt8, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_flags(arg1)
    ccall((:fido_dev_flags, libfido2), UInt8, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_info_vendor(arg1)
    ccall((:fido_dev_info_vendor, libfido2), Int16, (Ptr{fido_dev_info_t},), arg1)
end

function fido_dev_info_product(arg1)
    ccall((:fido_dev_info_product, libfido2), Int16, (Ptr{fido_dev_info_t},), arg1)
end

function fido_cbor_info_fwversion(arg1)
    ccall((:fido_cbor_info_fwversion, libfido2), UInt64, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_maxcredbloblen(arg1)
    ccall((:fido_cbor_info_maxcredbloblen, libfido2), UInt64, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_maxcredcntlst(arg1)
    ccall((:fido_cbor_info_maxcredcntlst, libfido2), UInt64, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_maxcredidlen(arg1)
    ccall((:fido_cbor_info_maxcredidlen, libfido2), UInt64, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_maxlargeblob(arg1)
    ccall((:fido_cbor_info_maxlargeblob, libfido2), UInt64, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_maxmsgsiz(arg1)
    ccall((:fido_cbor_info_maxmsgsiz, libfido2), UInt64, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_maxrpid_minpinlen(arg1)
    ccall((:fido_cbor_info_maxrpid_minpinlen, libfido2), UInt64, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_minpinlen(arg1)
    ccall((:fido_cbor_info_minpinlen, libfido2), UInt64, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_uv_attempts(arg1)
    ccall((:fido_cbor_info_uv_attempts, libfido2), UInt64, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_uv_modality(arg1)
    ccall((:fido_cbor_info_uv_modality, libfido2), UInt64, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_cbor_info_rk_remaining(arg1)
    ccall((:fido_cbor_info_rk_remaining, libfido2), Int64, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_dev_has_pin(arg1)
    ccall((:fido_dev_has_pin, libfido2), Bool, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_has_uv(arg1)
    ccall((:fido_dev_has_uv, libfido2), Bool, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_is_fido2(arg1)
    ccall((:fido_dev_is_fido2, libfido2), Bool, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_is_winhello(arg1)
    ccall((:fido_dev_is_winhello, libfido2), Bool, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_supports_credman(arg1)
    ccall((:fido_dev_supports_credman, libfido2), Bool, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_supports_cred_prot(arg1)
    ccall((:fido_dev_supports_cred_prot, libfido2), Bool, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_supports_permissions(arg1)
    ccall((:fido_dev_supports_permissions, libfido2), Bool, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_supports_pin(arg1)
    ccall((:fido_dev_supports_pin, libfido2), Bool, (Ptr{fido_dev_t},), arg1)
end

function fido_dev_supports_uv(arg1)
    ccall((:fido_dev_supports_uv, libfido2), Bool, (Ptr{fido_dev_t},), arg1)
end

function fido_cbor_info_new_pin_required(arg1)
    ccall((:fido_cbor_info_new_pin_required, libfido2), Bool, (Ptr{fido_cbor_info_t},), arg1)
end

function fido_dev_largeblob_get(arg1, arg2, arg3, arg4, arg5)
    ccall((:fido_dev_largeblob_get, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{Cuchar}, Csize_t, Ptr{Ptr{Cuchar}}, Ptr{Csize_t}), arg1, arg2, arg3, arg4, arg5)
end

function fido_dev_largeblob_set(arg1, arg2, arg3, arg4, arg5, arg6)
    ccall((:fido_dev_largeblob_set, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{Cuchar}, Csize_t, Ptr{Cuchar}, Csize_t, Ptr{Cchar}), arg1, arg2, arg3, arg4, arg5, arg6)
end

function fido_dev_largeblob_remove(arg1, arg2, arg3, arg4)
    ccall((:fido_dev_largeblob_remove, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{Cuchar}, Csize_t, Ptr{Cchar}), arg1, arg2, arg3, arg4)
end

function fido_dev_largeblob_get_array(arg1, arg2, arg3)
    ccall((:fido_dev_largeblob_get_array, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{Ptr{Cuchar}}, Ptr{Csize_t}), arg1, arg2, arg3)
end

function fido_dev_largeblob_set_array(arg1, arg2, arg3, arg4)
    ccall((:fido_dev_largeblob_set_array, libfido2), Cint, (Ptr{fido_dev_t}, Ptr{Cuchar}, Csize_t, Ptr{Cchar}), arg1, arg2, arg3, arg4)
end

const FIDO_ERR_SUCCESS = 0x00

const FIDO_ERR_INVALID_COMMAND = 0x01

const FIDO_ERR_INVALID_PARAMETER = 0x02

const FIDO_ERR_INVALID_LENGTH = 0x03

const FIDO_ERR_INVALID_SEQ = 0x04

const FIDO_ERR_TIMEOUT = 0x05

const FIDO_ERR_CHANNEL_BUSY = 0x06

const FIDO_ERR_LOCK_REQUIRED = 0x0a

const FIDO_ERR_INVALID_CHANNEL = 0x0b

const FIDO_ERR_CBOR_UNEXPECTED_TYPE = 0x11

const FIDO_ERR_INVALID_CBOR = 0x12

const FIDO_ERR_MISSING_PARAMETER = 0x14

const FIDO_ERR_LIMIT_EXCEEDED = 0x15

const FIDO_ERR_UNSUPPORTED_EXTENSION = 0x16

const FIDO_ERR_FP_DATABASE_FULL = 0x17

const FIDO_ERR_LARGEBLOB_STORAGE_FULL = 0x18

const FIDO_ERR_CREDENTIAL_EXCLUDED = 0x19

const FIDO_ERR_PROCESSING = 0x21

const FIDO_ERR_INVALID_CREDENTIAL = 0x22

const FIDO_ERR_USER_ACTION_PENDING = 0x23

const FIDO_ERR_OPERATION_PENDING = 0x24

const FIDO_ERR_NO_OPERATIONS = 0x25

const FIDO_ERR_UNSUPPORTED_ALGORITHM = 0x26

const FIDO_ERR_OPERATION_DENIED = 0x27

const FIDO_ERR_KEY_STORE_FULL = 0x28

const FIDO_ERR_NOT_BUSY = 0x29

const FIDO_ERR_NO_OPERATION_PENDING = 0x2a

const FIDO_ERR_UNSUPPORTED_OPTION = 0x2b

const FIDO_ERR_INVALID_OPTION = 0x2c

const FIDO_ERR_KEEPALIVE_CANCEL = 0x2d

const FIDO_ERR_NO_CREDENTIALS = 0x2e

const FIDO_ERR_USER_ACTION_TIMEOUT = 0x2f

const FIDO_ERR_NOT_ALLOWED = 0x30

const FIDO_ERR_PIN_INVALID = 0x31

const FIDO_ERR_PIN_BLOCKED = 0x32

const FIDO_ERR_PIN_AUTH_INVALID = 0x33

const FIDO_ERR_PIN_AUTH_BLOCKED = 0x34

const FIDO_ERR_PIN_NOT_SET = 0x35

const FIDO_ERR_PIN_REQUIRED = 0x36

const FIDO_ERR_PIN_POLICY_VIOLATION = 0x37

const FIDO_ERR_PIN_TOKEN_EXPIRED = 0x38

const FIDO_ERR_REQUEST_TOO_LARGE = 0x39

const FIDO_ERR_ACTION_TIMEOUT = 0x3a

const FIDO_ERR_UP_REQUIRED = 0x3b

const FIDO_ERR_UV_BLOCKED = 0x3c

const FIDO_ERR_UV_INVALID = 0x3f

const FIDO_ERR_UNAUTHORIZED_PERM = 0x40

const FIDO_ERR_ERR_OTHER = 0x7f

const FIDO_ERR_SPEC_LAST = 0xdf

const FIDO_OK = FIDO_ERR_SUCCESS

const FIDO_ERR_TX = -1

const FIDO_ERR_RX = -2

const FIDO_ERR_RX_NOT_CBOR = -3

const FIDO_ERR_RX_INVALID_CBOR = -4

const FIDO_ERR_INVALID_PARAM = -5

const FIDO_ERR_INVALID_SIG = -6

const FIDO_ERR_INVALID_ARGUMENT = -7

const FIDO_ERR_USER_PRESENCE_REQUIRED = -8

const FIDO_ERR_INTERNAL = -9

const FIDO_ERR_NOTFOUND = -10

const FIDO_ERR_COMPRESS = -11

const CTAP_AUTHDATA_USER_PRESENT = 0x01

const CTAP_AUTHDATA_USER_VERIFIED = 0x04

const CTAP_AUTHDATA_ATT_CRED = 0x40

const CTAP_AUTHDATA_EXT_DATA = 0x80

const CTAP_CMD_PING = 0x01

const CTAP_CMD_MSG = 0x03

const CTAP_CMD_LOCK = 0x04

const CTAP_CMD_INIT = 0x06

const CTAP_CMD_WINK = 0x08

const CTAP_CMD_CBOR = 0x10

const CTAP_CMD_CANCEL = 0x11

const CTAP_KEEPALIVE = 0x3b

const CTAP_FRAME_INIT = 0x80

const CTAP_CBOR_MAKECRED = 0x01

const CTAP_CBOR_ASSERT = 0x02

const CTAP_CBOR_GETINFO = 0x04

const CTAP_CBOR_CLIENT_PIN = 0x06

const CTAP_CBOR_RESET = 0x07

const CTAP_CBOR_NEXT_ASSERT = 0x08

const CTAP_CBOR_BIO_ENROLL = 0x09

const CTAP_CBOR_CRED_MGMT = 0x0a

const CTAP_CBOR_LARGEBLOB = 0x0c

const CTAP_CBOR_CONFIG = 0x0d

const CTAP_CBOR_BIO_ENROLL_PRE = 0x40

const CTAP_CBOR_CRED_MGMT_PRE = 0x41

const CTAP_PIN_PROTOCOL1 = 1

const CTAP_PIN_PROTOCOL2 = 2

const U2F_CMD_REGISTER = 0x01

const U2F_CMD_AUTH = 0x02

const U2F_AUTH_SIGN = 0x03

const U2F_AUTH_CHECK = 0x07

const SW1_MORE_DATA = 0x61

const SW_WRONG_LENGTH = 0x6700

const SW_CONDITIONS_NOT_SATISFIED = 0x6985

const SW_WRONG_DATA = 0x6a80

const SW_NO_ERROR = 0x9000

const CTAP_CID_BROADCAST = 0xffffffff

const CTAP_INIT_HEADER_LEN = 7

const CTAP_CONT_HEADER_LEN = 5

const CTAP_MAX_REPORT_LEN = 64

const CTAP_MIN_REPORT_LEN = CTAP_INIT_HEADER_LEN + 1

const FIDO_RANDOM_DEV = "/dev/urandom"

const FIDO_MAXMSG = 2048

const FIDO_CAP_WINK = 0x01

const FIDO_CAP_CBOR = 0x04

const FIDO_CAP_NMSG = 0x08

const COSE_UNSPEC = 0

const COSE_ES256 = -7

const COSE_EDDSA = -8

const COSE_ECDH_ES256 = -25

const COSE_ES384 = -35

const COSE_RS256 = -257

const COSE_RS1 = -65535

const COSE_KTY_OKP = 1

const COSE_KTY_EC2 = 2

const COSE_KTY_RSA = 3

const COSE_P256 = 1

const COSE_P384 = 2

const COSE_ED25519 = 6

const FIDO_EXT_HMAC_SECRET = 0x01

const FIDO_EXT_CRED_PROTECT = 0x02

const FIDO_EXT_LARGEBLOB_KEY = 0x04

const FIDO_EXT_CRED_BLOB = 0x08

const FIDO_EXT_MINPINLEN = 0x10

const FIDO_CRED_PROT_UV_OPTIONAL = 0x01

const FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID = 0x02

const FIDO_CRED_PROT_UV_REQUIRED = 0x03

const FIDO_ENTATTEST_VENDOR = 1

const FIDO_ENTATTEST_PLATFORM = 2

const FIDO_UV_MODE_TUP = 0x0001

const FIDO_UV_MODE_FP = 0x0002

const FIDO_UV_MODE_PIN = 0x0004

const FIDO_UV_MODE_VOICE = 0x0008

const FIDO_UV_MODE_FACE = 0x0010

const FIDO_UV_MODE_LOCATION = 0x0020

const FIDO_UV_MODE_EYE = 0x0040

const FIDO_UV_MODE_DRAWN = 0x0080

const FIDO_UV_MODE_HAND = 0x0100

const FIDO_UV_MODE_NONE = 0x0200

const FIDO_UV_MODE_ALL = 0x0400

const FIDO_UV_MODE_EXT_PIN = 0x0800

const FIDO_UV_MODE_EXT_DRAWN = 0x1000

const FIDO_DEBUG = 0x01

const FIDO_DISABLE_U2F_FALLBACK = 0x02

# exports
const PREFIXES = ["fido_", "FIDO"]
for name in names(@__MODULE__; all=true), prefix in PREFIXES
    if startswith(string(name), prefix)
        @eval export $name
    end
end

end # module
