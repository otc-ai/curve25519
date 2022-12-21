export declare var curve25519_clamp: (curve: any) => any;
export declare function curve25519_(f: any, c: any, s: any): any[];
export declare var curve25519: {
    sign: (h: any, x: any, s: any) => any[] | undefined;
    verify: (v: any, h: any, P: any) => any[];
    keygen: (k: any) => {
        p: any[];
        s: any[];
        k: any;
    };
};
