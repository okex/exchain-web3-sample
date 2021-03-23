pragma solidity >=0.7.0 <0.8.0;

contract Storage {
    uint256 public index;
    mapping(uint256 => uint256) public map1;
    mapping(uint256 => uint256) public map2;
    mapping(uint256 => uint256) public map3;
    mapping(uint256 => uint256) public map4;
    mapping(uint256 => uint256) public map5;
    mapping(uint256 => uint256) public map6;
    mapping(uint256 => uint256) public map7;
    mapping(uint256 => uint256) public map8;
    mapping(uint256 => uint256) public map9;
    mapping(uint256 => uint256) public map10;


    function add() public {
        for (uint i = 0; i < 100; i++) {
            index += 1;
            map1[index] = index;
            map2[index] = index;
            map3[index] = index;
            map4[index] = index;
            map5[index] = index;
            map6[index] = index;
            map7[index] = index;
            map8[index] = index;
            map9[index] = index;
            map10[index] = index;
        }
    }


    function retrieve() public view returns (uint256){
        return index;
    }
}
