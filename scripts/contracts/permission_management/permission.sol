pragma solidity ^0.4.18;


/// @title Permission contract
/// @notice Only be called by permission_management contract except query interface 
contract Permission {

    struct Resource {
        // Contract address
        address cont;
        // Function hash
        bytes4 func;
    }

    address permissionManagementAddr = 0x00000000000000000000000000000000013241b2;
    Resource[] resources;
    bytes32 name;

    event ResourcesAdded(address[] _conts, bytes4[] _funcs);
    event ResourcesDeleted(address[] _conts, bytes4[] _funcs);
    event NameUpdated(bytes32 indexed _oldName, bytes32 indexed _name);
    
    modifier onlyPermissionManagement {
        require(permissionManagementAddr == msg.sender);
        _;
    }

    modifier notSame(bytes32 _name) {
        require(name != _name); 
        _;
    }

    /// @dev Constructor
    function Permission(bytes32 _name, address[] _conts, bytes4[] _funcs)
        public
    {
        name = _name;
        _addResources(_conts, _funcs);
    }

    /// @dev Add the resources
    function addResources(address[] _conts, bytes4[] _funcs)
        public
        onlyPermissionManagement
        returns (bool)
    {
        return _addResources(_conts, _funcs);
    }

    /// @dev Delete the resources
    function deleteResources(address[] _conts, bytes4[] _funcs)
        public
        onlyPermissionManagement
        returns (bool)
    {
        for (uint i = 0; i < _conts.length; i++)
            resourceDelete(_conts[i], _funcs[i]);

        ResourcesDeleted(_conts, _funcs);
        return true;
    }

    /// @dev Update permission's name
    function updateName(bytes32 _name)
        public
        onlyPermissionManagement
        notSame(_name)
        returns (bool)
    {
        NameUpdated(name, _name);
        name = _name; 
        return true;
    }

    /// @dev Destruct self
    function close() public onlyPermissionManagement {
        selfdestruct(msg.sender); 
    }

    /// @dev Check resource in the permission
    function inPermission(address cont, bytes4 func)
        public
        view
        returns (bool)
    {
        for (uint i = 0; i < resources.length; i++) {
            if (cont == resources[i].cont && func == resources[i].func)
                return true;
        }

        return false;
    }

    /// @dev Query the information of the permission
    function queryInfo()
        public
        view
        returns (bytes32 _name, address[] conts, bytes4[] funcs)
    {
        _name = name;

        for (uint i = 0; i < resources.length; i++) {
            conts[i] = resources[i].cont;
            funcs[i] = resources[i].func;
        }
    }

    /// @dev Delete the value of the resources
    function resourceDelete(address _cont, bytes4 _func)
        private 
        returns (bool)
    {
        var index = resourceIndex(_cont,  _func);
        // Not found
        if (index >= resources.length)
            return false;

        // Remove the gap
        // TODO Start from the bottom
        for (uint i = index; i < resources.length-1; i++)
            resources[i] = resources[i+1];

        // Also delete the last element
        delete resources[resources.length-1];
        resources.length--;
        return true;
    }

    /// @dev Get the index of the value in the resources
    /// @return The index. If i == length, means not find
    function resourceIndex(address _cont, bytes4 _func)
        private 
        view
        returns (uint i)
    {
        for (i = 0; i < resources.length; i++) {
            if (_cont == resources[i].cont && _func == resources[i].func)
                return i;
        }
    }

    function _addResources(address[] _conts, bytes4[] _funcs)
        private 
        returns (bool)
    {
        for (uint i = 0; i < _conts.length; i++) {
            Resource memory res = Resource(_conts[i], _funcs[i]);
            resources.push(res);
        }

        ResourcesAdded(_conts, _funcs);
        return true;
    }
}
