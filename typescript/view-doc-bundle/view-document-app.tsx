import * as React from "react";
import PassZeroAPIv1 from "../common-modules/passzero-api-v1";


interface IViewDocumentAppState {
    documentId: number;
    mimetype: string;
    name: string;

    // viewport dims
    vh: number;
    vw: number;
}


export default class ViewDocumentApp extends React.PureComponent<{}, IViewDocumentAppState> {
    pzAPI: PassZeroAPIv1;

    constructor(props) {
        super(props);

        this.pzAPI = new PassZeroAPIv1();
        this.state = {
            // filled in componentDidMount
            documentId: -1,
            mimetype: "",
            name: "",

            vw: -1,
            vh: -1
        };

        this.handleResize = this.handleResize.bind(this);
    }

    handleResize() {
        const elem = document.getElementsByTagName("main")[0];
        // read the window size and size appropriately
        const vw = elem.clientWidth;
        const vh = elem.clientHeight;

        this.setState({
            vh: vh,
            vw: vw
        });
    }

    componentDidMount() {
        const documentId = Number.parseInt((document.getElementById("document_id") as HTMLInputElement).value, 10);
        console.log(`Got documentId ${documentId}`);

        let mimetype = (document.getElementById("document_mimetype") as HTMLInputElement).value;
        console.log(`Got mimetype ${mimetype}`);

        const name = (document.getElementById("document_name") as HTMLInputElement).value;
        console.log(`Got document name ${name}`);

        if(mimetype.startsWith("text/")) {
            // for proper rendering
            mimetype = "text/plain";
        }

        this.setState({
            documentId: documentId,
            mimetype: mimetype,
            name: name
        });

        // listen for resize
        window.addEventListener("resize", this.handleResize);
        // and add viewport dims for the first time
        this.handleResize();
    }

    render() {


        return (<div>
            <h1>{ this.state.name }</h1>
            <object data={ `/api/v1/docs/${this.state.documentId}` }
                type={ this.state.mimetype }
                height={ this.state.vh }
                width={ this.state.vw * 0.9 }>
                    <p>some stuff inside</p>
                </object>
        </div>);
    }
}