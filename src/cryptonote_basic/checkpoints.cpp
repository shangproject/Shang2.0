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

#include "include_base_utils.h"

using namespace epee;

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "include_base_utils.h"
#include <sstream>
#include <random>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  //---------------------------------------------------------------------------
  checkpoints::checkpoints()
  {
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = null_hash;
    bool r = epee::string_tools::parse_tpod_from_hex_string(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    // return false if adding at a height we already have AND the hash is different
    if (m_points.count(height))
    {
      CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    m_points[height] = h;
    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool& is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    is_a_checkpoint = it != m_points.end();
    if(!is_a_checkpoint)
      return true;

    if(it->second == h)
    {
      MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
      return true;
    }else
    {
      MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h) const
  {
    bool ignored;
    return check_block(height, h, ignored);
  }
  //---------------------------------------------------------------------------


  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);

    if (it == m_points.begin())
      return true;

    --it;
    uint64_t checkpoint_height = it->first;
    return checkpoint_height < block_height;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    std::map< uint64_t, crypto::hash >::const_iterator highest = 
        std::max_element( m_points.begin(), m_points.end(),
                         ( boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _1) < 
                           boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _2 ) ) );
    return highest->first;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, crypto::hash>& checkpoints::get_points() const
  {
    return m_points;
  }

  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

  bool checkpoints::init_default_checkpoints()
  {
    ADD_CHECKPOINT(0,       "876f6313ea61cec03c444f9196219e7b186102a7baf26f77c164f9ac011a0e79");
    ADD_CHECKPOINT(1,       "9964c7492db7ff26de975318d1a3c9396b971ec3f6839e8bffb083ab80b7be41");
    ADD_CHECKPOINT(5,       "a0432b0ec103e4f5921eaea967fc1638d5dd62fd98b6ce75fae5aff3e6fd134f");
    ADD_CHECKPOINT(10,      "7a59762b36d1928a314bf82b7a6030ae2709790284d063361c23c2deff89736d");
    ADD_CHECKPOINT(15,      "c88c2cb74a3113ba8a4d9b29332db5163a6498e48c1c60f5271d38fb70e58a3a");
    ADD_CHECKPOINT(20,      "7374c3cbf9ed82f870938718d4bd64724901e15f54ec44346dc1cf466eafe058");
    ADD_CHECKPOINT(25,      "50d3fc0ca36f2e26e7ec24d66eac83e26e299754b09d81721da04c72177de80d");
    ADD_CHECKPOINT(35,      "bde0ba793195f39c43924f5c977a1eca155c1ff2b8e9b409a4451f07fd42ef0f");
    ADD_CHECKPOINT(50,      "d5fa39fbf87370c9d1aab09111a68939e3b6bcd8d595ab010b6664b7658ab13e");
    ADD_CHECKPOINT(75,      "17c3679a9663d068fb5e5051b01f338ee0026b52b40a4249b574712874c0b6b2");
    ADD_CHECKPOINT(100,     "db8ec1f162b0dd946db14d4d7519559014912eeecfd2e3ff9cad288188184efb");
    ADD_CHECKPOINT(150,     "bb74291cc5e487a471b724f2f1743483473e535d7f0dbc3693fae3d6ac5d16ea");
    ADD_CHECKPOINT(200,     "d84a68160cd5ae4310cf40cf05d54770776c63835cf3d08c2ac8f3a6ca7713b6");
    ADD_CHECKPOINT(300,     "03779989ba9fc6a6f6de84b18a8f589d61be5dc6ddb02dbd08cd8c3f8df88813");
    ADD_CHECKPOINT(400,     "4ec41449b361950f6b0103bc4710ebc5aa0da4dd0962eedc98ebc94a732452b9");
    ADD_CHECKPOINT(500,     "c19c2333b4c799462c0d3d2341ef22f4081dcf163a21bcaeb5e3f3d267a096fa");
    ADD_CHECKPOINT(1000,    "262447d5c02fc23c00e3003ee09e3267ced726ed03897976638a145ec9456423");
    ADD_CHECKPOINT(1500,    "3f772b9988e712f249c759b7cc4df5ce435cb733c43a9b26136184f2ee9f227c");
    ADD_CHECKPOINT(2000,    "e26984dd174ffc4f92b4c7ab64a59bda9fc92221603f0c198efcc45b6511d1a0");
    ADD_CHECKPOINT(3000,    "df25e210cc793d96397a6e7ffa96946c90aa5055979edbafb97c3b871269c84d");
    ADD_CHECKPOINT(4000,    "a3056bf96d43c3cfa3837cfdb16ba06746c57a1b26f947cfb6eebcc79868344e");
    ADD_CHECKPOINT(5000,    "abe082de7d9b8c7f7e978e8cbb92ad9ece28d768486d1c4d9cd6b4ecb8ddc6ba");
    ADD_CHECKPOINT(6000,    "8780939d3bb1aac66319f35d3c7624a005ecf8cadbeb9b07b3778b90006a0714");
    ADD_CHECKPOINT(7000,    "1f539428218f5ebc7e01ead7fbff54f8eb04f3231f5effb66d4bb7b6629b991e");    

    return true;
  }

  bool checkpoints::load_checkpoints_from_json(const std::string json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath);
    for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
	LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
	std::string blockhash = it->hash;
	LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
	ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(bool testnet)
  {
    std::vector<std::string> records;

    // All four MoneroPulse domains have DNSSEC on and valid
    static const std::vector<std::string> dns_urls = { "checkpoints.shangcoin.com"
    };

    static const std::vector<std::string> testnet_dns_urls = { "testpoints.shangcoin.com"
    };

    if (!tools::dns_utils::load_txt_records_from_dns(records, testnet ? testnet_dns_urls : dns_urls))
      return true; // why true ?

    for (const auto& record : records)
    {
      auto pos = record.find(":");
      if (pos != std::string::npos)
      {
        uint64_t height;
        crypto::hash hash;

        // parse the first part as uint64_t,
        // if this fails move on to the next record
        std::stringstream ss(record.substr(0, pos));
        if (!(ss >> height))
        {
    continue;
        }

        // parse the second part as crypto::hash,
        // if this fails move on to the next record
        std::string hashStr = record.substr(pos + 1);
        if (!epee::string_tools::parse_tpod_from_hex_string(hashStr, hash))
        {
    continue;
        }

        ADD_CHECKPOINT(height, hashStr);
      }
    }
    return true;
  }

  bool checkpoints::load_new_checkpoints(const std::string json_hashfile_fullpath, bool testnet, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(testnet);
    }

    return result;
  }
}
