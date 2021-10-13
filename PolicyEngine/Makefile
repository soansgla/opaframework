clean:
	@rm -rf ./build

create_bundle: clean
	@mkdir ./build
	@cp -R ./bundle/* ./build
	#@echo "{\"revision\": "`git --git-dir ./bundle/.git log --format=\"%H\" -n 1`"}" > ./build/.manifest
	@echo "{\"revision\": \"1.0\"}" > ./build/.manifest
	@cd ./build; tar --exclude='.git' --exclude='.DS_Store' --exclude='build' -cvzf ./bundle.tar.gz .; zip -r ./bundle.zip ./bundle.tar.gz

run_local: create_bundle
	docker build -t local -f ./Dockerfile.local . && docker run -p8181:8181 -it local
