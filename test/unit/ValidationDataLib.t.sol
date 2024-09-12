import "contracts/lib/ValidationDataLib.sol";

import "contracts/DataTypes.sol";
import {
    ValidationData as ValidationDataStruct,
    _packValidationData
} from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";
import "forge-std/Test.sol";

contract ValidationDataLibTest is Test {
    function setUp() public {
        // Setup is empty as we're using fresh state for each test
    }

    function test_intersect(
        uint48 validAfter_a,
        uint48 validAfter_b,
        uint48 validUntil_a,
        uint48 validUntil_b
    )
        public
    {
        vm.assume(validAfter_a != 0);
        vm.assume(validAfter_b != 0);
        vm.assume(validUntil_a != 0);
        vm.assume(validUntil_b != 0);
        ValidationData vd_a = ValidationData.wrap(_packValidationData(false, validUntil_a, validAfter_a));
        ValidationData vd_b = ValidationData.wrap(_packValidationData(false, validUntil_b, validAfter_b));

        ValidationData result = ValidationDataLib.intersect(vd_a, vd_b);

        (uint48 validUntil, uint48 validAfter) = _unpackValidationData(ValidationData.unwrap(result));

        if (validAfter_a > validAfter_b) {
            assertEq(validAfter, validAfter_a, "validAfter_a > validAfter_b");
        } else {
            assertEq(validAfter, validAfter_b, "validAfter_a <= validAfter_b");
        }
        if (validUntil_a < validUntil_b) {
            assertEq(validUntil, validUntil_a, "validUntil_a < validUntil_b");
        } else {
            assertEq(validUntil, validUntil_b, "validUntil_a >= validUntil_b");
        }
    }

    function _unpackValidationData(uint256 packedData) internal pure returns (uint48 validUntil, uint48 validAfter) {
        validUntil = uint48(packedData >> 160);
        validAfter = uint48(packedData >> (160 + 48));
    }
}
