// SPDX-License-Identifier: MIT
pragma solidity ^0.8.1;
contract Sensor
{
    uint256 public g;
    string status = "duplicate entry";
    function addUnD(uint256 _g)public returns(string memory result){
        if(_g==g){
            return status;
        }
        else{
            g = _g;
            }
    }
    function inspectUnD(uint256 _g) public view returns(uint32 result){
        if(_g == g){
            return 1;
        }
        else{
            return 2;
        }
    }
}
