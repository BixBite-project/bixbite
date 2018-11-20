// Copyright (c) 2014-2017, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <boost/foreach.hpp>
#include "include_base_utils.h"
using namespace epee;

#include "node_rpc_server.h"
#include "common/command_line.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "cryptonote_core/account.h"
#include "cryptonote_core/cryptonote_basic_impl.h"
#include "misc_language.h"
#include "crypto/hash.h"
#include "node_rpc_server_error_codes.h"

#include "wallet/api/wallet.h"

#define MAX_RESTRICTED_FAKE_OUTS_COUNT 40
#define MAX_RESTRICTED_GLOBAL_FAKE_OUTS_COUNT 500

namespace cryptonote
{


//------------------------------------------------------------------------------------------------------------------------------
node_rpc_server::node_rpc_server(
        core& cr
        , nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& p2p
        )
    : m_core(cr)
    , m_p2p(p2p)
{}
//-----------------------------------------------------------------------------------
string node_rpc_server::base64_decode(const string &encoded_data)
{
    return epee::string_encoding::base64_decode(encoded_data);
}
//-----------------------------------------------------------------------------------
string node_rpc_server::base64_encode(const string &data)
{
    return epee::string_encoding::base64_encode(data);
}
//-----------------------------------------------------------------------------------
void node_rpc_server::init_options(boost::program_options::options_description& desc)
{
    command_line::add_arg(desc, arg_rpc_bind_ip);
    command_line::add_arg(desc, arg_rpc_bind_port);
    command_line::add_arg(desc, arg_restricted_rpc);
    command_line::add_arg(desc, arg_user_agent);
}
//------------------------------------------------------------------------------------------------------------------------------
bool node_rpc_server::handle_command_line(
        const boost::program_options::variables_map& vm
        )
{
    m_bind_ip = command_line::get_arg(vm, arg_rpc_bind_ip);
    m_port = command_line::get_arg(vm, arg_rpc_bind_port);
    m_restricted = command_line::get_arg(vm, arg_restricted_rpc);
    return true;
}
//------------------------------------------------------------------------------------------------------------------------------
bool node_rpc_server::init(
        const boost::program_options::variables_map& vm
        )
{
    m_testnet = command_line::get_arg(vm, command_line::arg_testnet_on);
    std::string m_user_agent = command_line::get_arg(vm, command_line::arg_user_agent);

    m_net_server.set_threads_prefix("RPC");
    bool r = handle_command_line(vm);
    CHECK_AND_ASSERT_MES(r, false, "Failed to process command line in node_rpc_server");
    return epee::http_server_impl_base<node_rpc_server, connection_context>::init(m_port, m_bind_ip, m_user_agent);
}
//------------------------------------------------------------------------------------------------------------------------------
bool node_rpc_server::check_core_busy()
{
    if(m_p2p.get_payload_object().get_core().get_blockchain_storage().is_storing_blockchain())
    {
        return false;
    }
    return true;
}
#define CHECK_NODE_BUSY() do { if(!check_core_busy()){res.status =  NODE_RPC_STATUS_BUSY;return true;} } while(0)
//------------------------------------------------------------------------------------------------------------------------------
bool node_rpc_server::check_core_ready()
{
    if(!m_p2p.get_payload_object().is_synchronized())
    {
        return false;
    }
    return check_core_busy();
}
#define CHECK_NODE_READY() do { if(!check_core_ready()){res.status =  NODE_RPC_STATUS_BUSY;return true;} } while(0)

//------------------------------------------------------------------------------------------------------------------------------
bool node_rpc_server::on_helloworld(const COMMAND_NODE_RPC_HELLOWORLD::request& req, COMMAND_NODE_RPC_HELLOWORLD::response& res)
{
    CHECK_NODE_BUSY();
    res.phrase = "Hello, world!";
    res.status = NODE_RPC_STATUS_OK;
    return true;
}
//------------------------------------------------------------------------------------------------------------------------------
bool node_rpc_server::on_createaccount(COMMAND_NODE_RPC_CREATE_ACCOUNT::request& req, COMMAND_NODE_RPC_CREATE_ACCOUNT::response& res)
{
    CHECK_NODE_BUSY();

    std::string uuid=boost::uuids::to_string(boost::uuids::random_generator()());

    Monero::WalletImpl wal(false);
    wal.init("http://127.0.0.1:44041",0);

    if(!wal.create(uuid,req.password,req.language))
    {
        res.status = NODE_RPC_ERROR_CREATE;
        return false;
    }
    if(!wal.open(uuid,req.password))
    {
        res.status = NODE_RPC_ERROR_OPEN;
        return false;
    }

    wal.setRefreshFromBlockHeight(wal.daemonBlockChainHeight()-1);
    wal.refresh();

    res.address=wal.mainAddress();
    res.account=base64_encode(uuid);
    res.seed=wal.seed();
    res.view_key=wal.publicViewKey();



    if(!wal.store(""))
    {
        wal.close(true);
        res.status =NODE_RPC_ERROR_STORE;
        return false;
    }

    wal.close(true);

    res.status = NODE_RPC_STATUS_OK;
    return true;
}

//------------------------------------------------------------------------------------------------------------------------------

bool node_rpc_server::on_get_walletbalance(COMMAND_NODE_RPC_GETWALLETBALANCE::request& req, COMMAND_NODE_RPC_GETWALLETBALANCE::response& res)
{
    CHECK_NODE_BUSY();

    Monero::WalletImpl wal(false);
    wal.init("http://127.0.0.1:44041",0);
    if(!wal.open(base64_decode(req.account),req.password))
    {
        res.status = NODE_RPC_ERROR_OPEN;
        return false;
    }

    wal.refresh();

    res.balance=wal.balance();
    res.unlocked_balance=wal.unlockedBalance();

    wal.close(true);

    res.status = NODE_RPC_STATUS_OK;
    return true;
}

//------------------------------------------------------------------------------------------------------------------------------

bool node_rpc_server::on_get_seed(COMMAND_NODE_RPC_GET_SEED::request& req, COMMAND_NODE_RPC_GET_SEED::response& res)
{
    CHECK_NODE_BUSY();

    Monero::WalletImpl wal(false);
    wal.init("http://127.0.0.1:44041",0);
    if(!wal.open(base64_decode(req.account),req.password))
    {
        res.status = NODE_RPC_ERROR_OPEN;
        return false;
    }


    res.seed=wal.seed();

    wal.close(true);

    res.status = NODE_RPC_STATUS_OK;
    return true;
}

//------------------------------------------------------------------------------------------------------------------------------

bool node_rpc_server::on_restore_account(COMMAND_NODE_RPC_RESTORE_ACCOUNT::request& req, COMMAND_NODE_RPC_RESTORE_ACCOUNT::response& res)
{
    CHECK_NODE_BUSY();

    std::string uuid=base64_encode(boost::uuids::to_string(boost::uuids::random_generator()()));

    Monero::WalletImpl wal(false);
    wal.init("http://127.0.0.1:44041",0);

    if(!wal.recover(uuid,req.seed))
    {
            res.status = NODE_RPC_ERROR_RECOVER;
            return false;
    }
    if(!wal.setPassword(req.password))
    {
            res.status = NODE_RPC_ERROR_SET_PASSWORD;
            wal.close(true);
            return false;
    }
    if(!wal.open(uuid,req.password))
    {
        res.status = NODE_RPC_ERROR_OPEN;
        return false;
    }

    res.address=wal.mainAddress();
    res.account=base64_encode(uuid);
    res.seed=wal.seed();
    res.view_key=wal.publicViewKey();

    wal.refresh();

    if(!wal.store(""))
    {
        wal.close(true);
        res.status =NODE_RPC_ERROR_STORE;
        return false;
    }

    wal.close(true);

    res.status = NODE_RPC_STATUS_OK;
    return true;
}
bool node_rpc_server::on_transfer(COMMAND_NODE_RPC_TRANSFER::request& req, COMMAND_NODE_RPC_TRANSFER::response& res)
{
    CHECK_NODE_BUSY();

    Monero::WalletImpl wal(false);
    wal.init("http://127.0.0.1:44041",0);
    if(!wal.open(base64_decode(req.account),req.password))
    {
        res.status = NODE_RPC_ERROR_OPEN;
        return false;
    }
    uint64_t amm=wal.amountFromString(req.amount);

    Monero::PendingTransaction *trans=wal.createTransaction(req.address,"",amm,5);
    if(!trans->commit())
    {
        res.status = NODE_RPC_ERROR_COMMIT_TX;
        wal.close(true);
        return false;
    }

    wal.close(true);

    res.status = NODE_RPC_STATUS_OK;
    return true;
}
bool node_rpc_server::on_get_transfer_fee(COMMAND_NODE_RPC_GET_TRANSFER_FEE::request& req, COMMAND_NODE_RPC_GET_TRANSFER_FEE::response& res)
{
    CHECK_NODE_BUSY();

    Monero::WalletImpl wal(false);
    wal.init("http://127.0.0.1:44041",0);
    if(!wal.open(base64_decode(req.account),req.password))
    {
        res.status = NODE_RPC_ERROR_OPEN;
        return false;
    }

    uint64_t amm=wal.amountFromString(req.amount);
    Monero::PendingTransaction *trans=wal.createTransaction(req.address,"",amm,5);

   // res.fee=trans->fee();

    wal.close(true);

    res.status = NODE_RPC_STATUS_OK;
    return true;
}
//------------------------------------------------------------------------------------------------------------------------------
// equivalent of strstr, but with arbitrary bytes (ie, NULs)
// This does not differentiate between "not found" and "found at offset 0"

const command_line::arg_descriptor<std::string> node_rpc_server::arg_rpc_bind_ip   = {
    "node-rpc-bind-ip"
    , "IP for NODE RPC server"
    , "127.0.0.1"
};

const command_line::arg_descriptor<std::string> node_rpc_server::arg_rpc_bind_port = {
    "node-rpc-bind-port"
    , "Port for NODE RPC server"
    , std::to_string(config::NODE_RPC_DEFAULT_PORT)
};


const command_line::arg_descriptor<bool> node_rpc_server::arg_restricted_rpc = {
    "restricted-node-rpc"
    , "Restrict NODE RPC to view only commands"
    , false
};

const command_line::arg_descriptor<std::string> node_rpc_server::arg_user_agent = {
    "node-user-agent"
    , "Restrict NODE RPC to clients using this user agent"
    , ""
};

}  // namespace cryptonote
