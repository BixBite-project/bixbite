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

#pragma once
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_core/cryptonote_basic.h"
#include "cryptonote_core/difficulty.h"
#include "wallet/wallet2_api.h"
#include "crypto/hash.h"

namespace cryptonote
{
//-----------------------------------------------
#define NODE_RPC_STATUS_OK   "OK"
#define NODE_RPC_STATUS_BUSY   "BUSY"
#define NODE_RPC_STATUS_NOT_MINING "NOT MINING"

// When making *any* change here, bump minor
// If the change is incompatible, then bump major and set minor to 0
// This ensures CORE_RPC_VERSION always increases, that every change
// has its own version, and that clients can just test major to see
// whether they can talk to a given daemon without having to know in
// advance which version they will stop working with
// Don't go over 32767 for any of these
#define NODE_RPC_VERSION_MAJOR 0
#define NODE_RPC_VERSION_MINOR 1
#define NODE_RPC_VERSION (((NODE_RPC_VERSION_MAJOR)<<16)|(NODE_RPC_VERSION_MINOR))

struct COMMAND_NODE_RPC_GETWALLETBALANCE
{
    struct request {
        std::string account;
        std::string password;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account)
        KV_SERIALIZE(password)
        END_KV_SERIALIZE_MAP()
    };
    struct response {

        int64_t result;
        uint64_t balance;
        uint64_t unlocked_balance;
        std::string status;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(result)
        KV_SERIALIZE(balance)
        KV_SERIALIZE(unlocked_balance)
        KV_SERIALIZE(status)
        END_KV_SERIALIZE_MAP()
    };
};

struct COMMAND_NODE_RPC_CREATE_ACCOUNT {
    struct request {
        std::string password;
        std::string language;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(password)
        KV_SERIALIZE(language)
        END_KV_SERIALIZE_MAP()
    };
    struct response {
        int64_t result;
        std::string address;
        std::string view_key;
        std::string account;
        std::string seed;
        std::string status;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(result)
        KV_SERIALIZE(address)
        KV_SERIALIZE(view_key)
        KV_SERIALIZE(account)
        KV_SERIALIZE(seed)
        KV_SERIALIZE(status)
        END_KV_SERIALIZE_MAP()
    };
};

struct COMMAND_NODE_RPC_GET_SEED {
    struct request {
        std::string account;
        std::string password;
        std::string language;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account)
        KV_SERIALIZE(password)
        KV_SERIALIZE(language)
        END_KV_SERIALIZE_MAP()
    };
    struct response {
        int64_t result;
        std::string seed;
        std::string status;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(result)
        KV_SERIALIZE(seed)
        KV_SERIALIZE(status)
        END_KV_SERIALIZE_MAP()
    };
};

struct COMMAND_NODE_RPC_RESTORE_ACCOUNT {
    struct request {
        std::string seed;
        std::string password;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(seed)
        KV_SERIALIZE(password)
        END_KV_SERIALIZE_MAP()
    };
    struct response {
        int64_t result;
        std::string address;
        std::string view_key;
        std::string account;
        std::string seed;
        std::string status;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(result)
        KV_SERIALIZE(address)
        KV_SERIALIZE(view_key)
        KV_SERIALIZE(account)
        KV_SERIALIZE(seed)
        KV_SERIALIZE(status)
        END_KV_SERIALIZE_MAP()
    };
};

struct COMMAND_NODE_RPC_TRANSFER {
    struct request {
        std::string account;
        std::string password;
        std::string address;
        std::string amount;
        bool is_sweep_all;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account)
        KV_SERIALIZE(password)
        KV_SERIALIZE(address)
        KV_SERIALIZE(amount)
        KV_SERIALIZE(is_sweep_all)
        END_KV_SERIALIZE_MAP()
    };
    struct response {
        int64_t result;
        std::string status;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(result)
        KV_SERIALIZE(status)
        END_KV_SERIALIZE_MAP()
    };
};

struct COMMAND_NODE_RPC_GET_TRANSFER_FEE {
    struct request {
        std::string account;
        std::string password;
        std::string address;
        std::string amount;
        bool is_sweep_all;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account)
        KV_SERIALIZE(password)
        KV_SERIALIZE(address)
        KV_SERIALIZE(amount)
        KV_SERIALIZE(is_sweep_all)
        END_KV_SERIALIZE_MAP()
    };
    struct response {
        int64_t result;
        uint64_t fee;
        std::string status;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(result)
        KV_SERIALIZE(fee)
        KV_SERIALIZE(status)
        END_KV_SERIALIZE_MAP()
    };
};

struct transfer_details
{
  uint64_t amount;
  std::string tx_hash;
  uint64_t tx_height;
  int direction;
  std::string datetime;


  BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(amount)
    KV_SERIALIZE(tx_hash)
    KV_SERIALIZE(tx_height)
    KV_SERIALIZE(direction)
    KV_SERIALIZE(datetime)
  END_KV_SERIALIZE_MAP()
};

struct COMMAND_NODE_RPC_GET_TRANSFER_HISTORY {
    struct request {
        std::string account;
        std::string password;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account)
        KV_SERIALIZE(password)
        END_KV_SERIALIZE_MAP()
    };
    struct response {

        std::string status;
        std::list<transfer_details> transfers;

        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(transfers)
          KV_SERIALIZE(status)
        END_KV_SERIALIZE_MAP()
    };
};
struct COMMAND_NODE_RPC_GET_TRANSFER_DETAIL {
    struct request {
        std::string account;
        std::string password;
        std::string tx_id;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(account)
        KV_SERIALIZE(password)
        KV_SERIALIZE(tx_id)
        END_KV_SERIALIZE_MAP()
    };
    struct response {

        std::string status;

        uint64_t amount;
        uint64_t fee;
        std::string tx_hash;
        uint64_t tx_height;
        int direction;
        std::string datetime;
        uint64_t confirmations;
        bool isFailed;
        bool isPending;

        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(amount)
          KV_SERIALIZE(tx_hash)
          KV_SERIALIZE(tx_height)
          KV_SERIALIZE(direction)
          KV_SERIALIZE(datetime)
          KV_SERIALIZE(confirmations)
          KV_SERIALIZE(isFailed)
          KV_SERIALIZE(isPending)
          KV_SERIALIZE(fee)
          KV_SERIALIZE(status)
        END_KV_SERIALIZE_MAP()
    };
};
}
