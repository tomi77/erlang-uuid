all: build

clean:
	rm -f src/*.beam


build:
	erlc -o src src/uuid.erl

build-test:
	@erlc -DTEST -o src src/uuid.erl

test: build-test
	@cd src; erl -eval 'eunit:test(uuid).' -s init stop -noshell
