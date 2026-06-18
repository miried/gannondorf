#include <stdio.h>

extern "C" int fixture_no_refs(int value)
{
	return (value * 3) + 7;
}

extern "C" {
int fixture_global_value = 11;
}

extern "C" int fixture_uses_global(int value)
{
	fixture_global_value += value;
	return fixture_global_value;
}

extern "C" int fixture_calls_function(int value)
{
	return fixture_no_refs(value) - 2;
}

int main(void)
{
	printf("basic fixture\n");
	return fixture_calls_function(2) + fixture_uses_global(3);
}
