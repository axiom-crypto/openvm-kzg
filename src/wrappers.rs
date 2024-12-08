use core::ops::SubAssign;

use axvm_ecc_guest::Group;
use bls12_381::G1Affine;

pub struct G1AffineGroup(pub G1Affine);

// impl Group for G1AffineGroup {
//     type SelfRef<'a>
//         = &'a Self
//     where
//         Self: 'a;

//     fn identity() -> Self {
//         G1AffineGroup(G1Affine::identity())
//     }

//     fn is_identity(&self) -> bool {
//         self.0.is_identity().into()
//     }

//     fn double(&self) -> Self {
//         G1AffineGroup(self.0.double())
//     }

//     fn double_assign(&mut self) {
//         self.0;
//     }
// }

// impl<'a> SubAssign<&'a G1AffineGroup> for G1AffineGroup {
//     fn sub_assign(&mut self, rhs: &'a G1AffineGroup) {
//         self.0 = self.0 - rhs.0;
//     }
// }
