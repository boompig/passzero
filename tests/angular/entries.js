describe("PassZeroCtrl", function() {
    "use strict";

    beforeEach(angular.mock.module("PassZero"));

    var $controller;

    beforeEach(inject(function(_$controller_) {
        $controller = _$controller_;
    }));

    /**
     * Test the searchEntries method
     */
    describe("searchEntries", function() {
        var ctrl;

        beforeEach(function() {
            let $scope = {};
            ctrl = $controller("PassZeroCtrl", {
                $scope: $scope
            });
        });

        it("finds the correct entry in case-insensitive manner based on account name", function() {
            let entries = [
                {
                    account: "apple",
                    username: "test@test.com",
                    password: "foo",
                },
                {
                    account: "github",
                    username: "foo@bar.baz",
                    password: "foobar"
                },
                {
                    account: "dropbox",
                    username: "x@y.z",
                    password: "xyzabc123"
                },
                {
                    account: "apples and other fruits",
                    username: "farmer jo",
                    password: "how do you like them apples??"
                },
            ];
            ctrl.entries = entries;
            let actualEntries = ctrl.searchEntries("Apple");
            let expectedEntries = [entries[0], entries[3]];
            expect(actualEntries).toEqual(expectedEntries);
        });
    });
});
