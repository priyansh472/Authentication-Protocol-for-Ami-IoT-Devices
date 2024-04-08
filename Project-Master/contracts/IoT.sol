// SPDX-License-Identifier: MIT
pragma solidity ^0.8.1;
contract IoT{
    uint256 public alpha;
    uint256 public t;
    string status = "duplicate entry";
    function addUnD(uint256 _alpha,uint256 _t)public returns(string memory result){
        if(_alpha==alpha && _t==t){
            return status;
        }
        else{alpha =_alpha;
            t = _t;
            }
    }
    function inspectUnD(uint256 _alpha,uint256 _t) public view returns(uint32 result){
        if(_alpha == alpha && _t == t){
            return 1;
        }
        else{ 
            return 2;
        }
    }
}
