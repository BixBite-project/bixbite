// Copyright (c) 2014-2016, The Monero Project
// Copyright (c) 2017-2018, The Bixbite Project
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

#pragma  once 

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>

#include "net/http_server_impl_base.h"
#include "node_rpc_server_commands_defs.h"
#include "cryptonote_core/cryptonote_core.h"
#include "p2p/net_node.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "../contrib/epee/include/string_coding.h"
#include "../contrib/epee/include/time_helper.h"

// yes, epee doesn't properly use its full namespace when calling its
// functions from macros.  *sigh*
using namespace epee;

namespace cryptonote
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class node_rpc_server: public epee::http_server_impl_base<node_rpc_server>
  {
  public:

    static const command_line::arg_descriptor<std::string> arg_rpc_bind_ip;
    static const command_line::arg_descriptor<std::string> arg_rpc_bind_port;
    static const command_line::arg_descriptor<bool> arg_restricted_rpc;
    static const command_line::arg_descriptor<std::string> arg_user_agent;

    typedef epee::net_utils::connection_context_base connection_context;

    node_rpc_server(
        core& cr
      , nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& p2p
      );

    static void init_options(boost::program_options::options_description& desc);
    bool init(
        const boost::program_options::variables_map& vm
      );
    bool is_testnet() const { return m_testnet; }

    CHAIN_HTTP_TO_MAP2(connection_context); //forward http requests to uri map

    BEGIN_URI_MAP2()    
      BEGIN_JSON_RPC_MAP("/json_rpc")
        MAP_JON_RPC("createaccount",          on_createaccount,           COMMAND_NODE_RPC_CREATE_ACCOUNT)
        MAP_JON_RPC("getwalletbalance",       on_get_wallet_balance,       COMMAND_NODE_RPC_GETWALLETBALANCE)
        MAP_JON_RPC("getseed",                on_get_seed,                COMMAND_NODE_RPC_GET_SEED)
        MAP_JON_RPC("restoreaccount",         on_restore_account,         COMMAND_NODE_RPC_RESTORE_ACCOUNT)
        MAP_JON_RPC("transfer",               on_transfer,                COMMAND_NODE_RPC_TRANSFER)
        MAP_JON_RPC("gettransferfee",         on_get_transfer_fee,        COMMAND_NODE_RPC_GET_TRANSFER_FEE)
        MAP_JON_RPC("gettransferhistory",     on_get_transfer_history,    COMMAND_NODE_RPC_GET_TRANSFER_HISTORY)
        MAP_JON_RPC("gettransferdetail",      on_get_transfer_detail,     COMMAND_NODE_RPC_GET_TRANSFER_DETAIL)
      END_JSON_RPC_MAP()
    END_URI_MAP2()

    //json_rpc
    bool on_createaccount(COMMAND_NODE_RPC_CREATE_ACCOUNT::request& req, COMMAND_NODE_RPC_CREATE_ACCOUNT::response& res);
    bool on_get_wallet_balance(COMMAND_NODE_RPC_GETWALLETBALANCE::request& req, COMMAND_NODE_RPC_GETWALLETBALANCE::response& res);
    bool on_get_seed(COMMAND_NODE_RPC_GET_SEED::request& req, COMMAND_NODE_RPC_GET_SEED::response& res);
    bool on_restore_account(COMMAND_NODE_RPC_RESTORE_ACCOUNT::request& req, COMMAND_NODE_RPC_RESTORE_ACCOUNT::response& res);
    bool on_transfer(COMMAND_NODE_RPC_TRANSFER::request& req, COMMAND_NODE_RPC_TRANSFER::response& res);
    bool on_get_transfer_fee(COMMAND_NODE_RPC_GET_TRANSFER_FEE::request& req, COMMAND_NODE_RPC_GET_TRANSFER_FEE::response& res);
    bool on_get_transfer_history(COMMAND_NODE_RPC_GET_TRANSFER_HISTORY::request& req, COMMAND_NODE_RPC_GET_TRANSFER_HISTORY::response& res);
    bool on_get_transfer_detail(COMMAND_NODE_RPC_GET_TRANSFER_DETAIL::request& req, COMMAND_NODE_RPC_GET_TRANSFER_DETAIL::response& res);
    //-----------------------

private:

    bool handle_command_line(
        const boost::program_options::variables_map& vm
      );
    bool check_core_busy();
    bool check_core_ready();

    string base64_decode(const string &encoded_data);
    string base64_encode(const string &data);
    
    //utils
    core& m_core;
    nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& m_p2p;
    std::string m_port;
    std::string m_bind_ip;
    bool m_testnet;
    bool m_restricted;
  };
}
