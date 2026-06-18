extern "C" int fixture_if_else(int value)
{
	int result;

	if (value < 0) {
		result = -value;
	} else if (value == 0) {
		result = 42;
	} else {
		result = value + 5;
	}

	return result;
}

extern "C" int fixture_loop_sum(int count)
{
	int total = 0;
	int i = 0;

	while (i < count) {
		if (i & 1) {
			total += i * 2;
		} else {
			total += i;
		}
		++i;
	}

	return total;
}

extern "C" int fixture_nested_branches(int a, int b)
{
	int result = a;

	if (a > b) {
		result -= b;
		if (result > 10) {
			result = 10;
		}
	} else {
		result += b;
		if (result < 0) {
			result = 0;
		}
	}

	return result;
}

int main(void)
{
	return fixture_if_else(-4) + fixture_loop_sum(5) + fixture_nested_branches(9, 3);
}
