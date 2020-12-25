from squeak.core.elliptic import generate_random_scalar
from squeak.core.elliptic import scalar_to_bytes
from squeak.core.elliptic import scalar_from_bytes
from squeak.core.elliptic import scalar_sum
from squeak.core.elliptic import scalar_difference


class TestScalar(object):

    def test_encode_scalar(self):
        s = generate_random_scalar()
        s_bytes = scalar_to_bytes(s)
        s_from_bytes = scalar_from_bytes(s_bytes)

        assert s_from_bytes == s

    def test_add_subtract_scalar(self):
        x = generate_random_scalar()
        y = generate_random_scalar()
        z = scalar_sum(x, y)
        z_min_y = scalar_difference(z, y)

        assert z_min_y == x
