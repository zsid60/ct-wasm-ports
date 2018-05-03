(module
  (memory secret 1)
  
  ;; secret part of the alg
  (func $ss20
    (local $i i32)
    (local $scratch s32)
    (local $in_index i32)

    ;; init local 'u32 x[16]' --- (offset 16 - 31)
    (set_local $i (i32.const 64))
    (block
      (loop
	(br_if 1 (i32.ge_u (get_local $i) (i32.const 128)))
	  (set_local $in_index (i32.sub (get_local $i) (i32.const 64)))
	  (s32.store (get_local $i) (s32.load (get_local $in_index)))
	  (set_local $i (i32.add (get_local $i) (i32.const 4)))
	  (br 0)
	)
      )
    
    ;; bit-muck
    (set_local $i (i32.const 0))
    (set_local $scratch (s32.const 0))
    (block
      (loop
        (br_if 1 (i32.ge_u (get_local $i) (i32.const 10)))
          ;; x[ 4] = XOR(x[ 4],ROTATE(PLUS(x[ 0],x[12]), 7));
          (set_local $scratch (s32.add (s32.load (i32.const 64)) (s32.load (i32.const 112))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 7)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 80)) (get_local $scratch)))
	  (s32.store (i32.const 80) (get_local $scratch))
          ;; x[ 8] = XOR(x[ 8],ROTATE(PLUS(x[ 4],x[ 0]), 9));
          (set_local $scratch (s32.add (s32.load (i32.const 80)) (s32.load (i32.const 64))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 9)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 96)) (get_local $scratch)))
	  (s32.store (i32.const 96) (get_local $scratch))
          ;; x[12] = XOR(x[12],ROTATE(PLUS(x[ 8],x[ 4]),13));
          (set_local $scratch (s32.add (s32.load (i32.const 96)) (s32.load (i32.const 80))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 13)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 112)) (get_local $scratch)))
	  (s32.store (i32.const 112) (get_local $scratch))
	  ;; x[ 0] = XOR(x[ 0],ROTATE(PLUS(x[12],x[ 8]),18));
          (set_local $scratch (s32.add (s32.load (i32.const 112)) (s32.load (i32.const 96))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 18)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 64)) (get_local $scratch)))
	  (s32.store (i32.const 64) (get_local $scratch))
	  ;; x[ 9] = XOR(x[ 9],ROTATE(PLUS(x[ 5],x[ 1]), 7));
          (set_local $scratch (s32.add (s32.load (i32.const 84)) (s32.load (i32.const 68))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 7)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 100)) (get_local $scratch)))
	  (s32.store (i32.const 100) (get_local $scratch))
	  ;; x[13] = XOR(x[13],ROTATE(PLUS(x[ 9],x[ 5]), 9));
          (set_local $scratch (s32.add (s32.load (i32.const 100)) (s32.load (i32.const 84))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 9)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 116)) (get_local $scratch)))
	  (s32.store (i32.const 116) (get_local $scratch))
	  ;; x[ 1] = XOR(x[ 1],ROTATE(PLUS(x[13],x[ 9]),13));
          (set_local $scratch (s32.add (s32.load (i32.const 116)) (s32.load (i32.const 100))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 13)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 68)) (get_local $scratch)))
	  (s32.store (i32.const 68) (get_local $scratch))
	  ;; x[ 5] = XOR(x[ 5],ROTATE(PLUS(x[ 1],x[13]),18));
          (set_local $scratch (s32.add (s32.load (i32.const 68)) (s32.load (i32.const 116))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 18)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 84)) (get_local $scratch)))
	  (s32.store (i32.const 84) (get_local $scratch))
	  ;; x[14] = XOR(x[14],ROTATE(PLUS(x[10],x[ 6]), 7));
          (set_local $scratch (s32.add (s32.load (i32.const 104)) (s32.load (i32.const 88))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 7)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 120)) (get_local $scratch)))
	  (s32.store (i32.const 120) (get_local $scratch))
	  ;; x[ 2] = XOR(x[ 2],ROTATE(PLUS(x[14],x[10]), 9));
          (set_local $scratch (s32.add (s32.load (i32.const 120)) (s32.load (i32.const 104))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 9)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 72)) (get_local $scratch)))
	  (s32.store (i32.const 72) (get_local $scratch))
	  ;; x[ 6] = XOR(x[ 6],ROTATE(PLUS(x[ 2],x[14]),13));
          (set_local $scratch (s32.add (s32.load (i32.const 72)) (s32.load (i32.const 120))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 13)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 88)) (get_local $scratch)))
	  (s32.store (i32.const 88) (get_local $scratch))
	  ;; x[10] = XOR(x[10],ROTATE(PLUS(x[ 6],x[ 2]),18));
          (set_local $scratch (s32.add (s32.load (i32.const 88)) (s32.load (i32.const 72))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 18)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 104)) (get_local $scratch)))
	  (s32.store (i32.const 104) (get_local $scratch))
	  ;; x[ 3] = XOR(x[ 3],ROTATE(PLUS(x[15],x[11]), 7));
          (set_local $scratch (s32.add (s32.load (i32.const 124)) (s32.load (i32.const 108))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 7)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 76)) (get_local $scratch)))
	  (s32.store (i32.const 76) (get_local $scratch))
	  ;; x[ 7] = XOR(x[ 7],ROTATE(PLUS(x[ 3],x[15]), 9));
          (set_local $scratch (s32.add (s32.load (i32.const 76)) (s32.load (i32.const 124))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 9)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 92)) (get_local $scratch)))
	  (s32.store (i32.const 92) (get_local $scratch))
	  ;; x[11] = XOR(x[11],ROTATE(PLUS(x[ 7],x[ 3]),13));
          (set_local $scratch (s32.add (s32.load (i32.const 92)) (s32.load (i32.const 76))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 13)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 108)) (get_local $scratch)))
	  (s32.store (i32.const 108) (get_local $scratch))
	  ;; x[15] = XOR(x[15],ROTATE(PLUS(x[11],x[ 7]),18));
          (set_local $scratch (s32.add (s32.load (i32.const 108)) (s32.load (i32.const 92))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 18)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 124)) (get_local $scratch)))
	  (s32.store (i32.const 124) (get_local $scratch))
	  ;; x[ 1] = XOR(x[ 1],ROTATE(PLUS(x[ 0],x[ 3]), 7));
          (set_local $scratch (s32.add (s32.load (i32.const 64)) (s32.load (i32.const 76))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 7)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 68)) (get_local $scratch)))
	  (s32.store (i32.const 68) (get_local $scratch))
	  ;; x[ 2] = XOR(x[ 2],ROTATE(PLUS(x[ 1],x[ 0]), 9));
          (set_local $scratch (s32.add (s32.load (i32.const 68)) (s32.load (i32.const 64))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 9)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 72)) (get_local $scratch)))
	  (s32.store (i32.const 72) (get_local $scratch))
	  ;; x[ 3] = XOR(x[ 3],ROTATE(PLUS(x[ 2],x[ 1]),13));
          (set_local $scratch (s32.add (s32.load (i32.const 72)) (s32.load (i32.const 68))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 13)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 76)) (get_local $scratch)))
	  (s32.store (i32.const 76) (get_local $scratch))
	  ;; x[ 0] = XOR(x[ 0],ROTATE(PLUS(x[ 3],x[ 2]),18));
          (set_local $scratch (s32.add (s32.load (i32.const 76)) (s32.load (i32.const 72))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 18)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 64)) (get_local $scratch)))
	  (s32.store (i32.const 64) (get_local $scratch))
	  ;; x[ 6] = XOR(x[ 6],ROTATE(PLUS(x[ 5],x[ 4]), 7));
          (set_local $scratch (s32.add (s32.load (i32.const 84)) (s32.load (i32.const 80))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 7)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 88)) (get_local $scratch)))
	  (s32.store (i32.const 88) (get_local $scratch))
	  ;; x[ 7] = XOR(x[ 7],ROTATE(PLUS(x[ 6],x[ 5]), 9));
          (set_local $scratch (s32.add (s32.load (i32.const 88)) (s32.load (i32.const 84))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 9)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 92)) (get_local $scratch)))
	  (s32.store (i32.const 92) (get_local $scratch))
	  ;; x[ 4] = XOR(x[ 4],ROTATE(PLUS(x[ 7],x[ 6]),13));
          (set_local $scratch (s32.add (s32.load (i32.const 92)) (s32.load (i32.const 88))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 13)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 80)) (get_local $scratch)))
	  (s32.store (i32.const 80) (get_local $scratch))
	  ;; x[ 5] = XOR(x[ 5],ROTATE(PLUS(x[ 4],x[ 7]),18));
          (set_local $scratch (s32.add (s32.load (i32.const 80)) (s32.load (i32.const 92))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 18)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 84)) (get_local $scratch)))
	  (s32.store (i32.const 84) (get_local $scratch))
	  ;; x[11] = XOR(x[11],ROTATE(PLUS(x[10],x[ 9]), 7));
          (set_local $scratch (s32.add (s32.load (i32.const 104)) (s32.load (i32.const 100))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 7)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 108)) (get_local $scratch)))
	  (s32.store (i32.const 108) (get_local $scratch))
	  ;; x[ 8] = XOR(x[ 8],ROTATE(PLUS(x[11],x[10]), 9));
          (set_local $scratch (s32.add (s32.load (i32.const 108)) (s32.load (i32.const 104))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 9)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 96)) (get_local $scratch)))
	  (s32.store (i32.const 96) (get_local $scratch))
	  ;; x[ 9] = XOR(x[ 9],ROTATE(PLUS(x[ 8],x[11]),13));
          (set_local $scratch (s32.add (s32.load (i32.const 96)) (s32.load (i32.const 108))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 13)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 100)) (get_local $scratch)))
	  (s32.store (i32.const 100) (get_local $scratch))
	  ;; x[10] = XOR(x[10],ROTATE(PLUS(x[ 9],x[ 8]),18));
          (set_local $scratch (s32.add (s32.load (i32.const 100)) (s32.load (i32.const 96))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 18)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 104)) (get_local $scratch)))
	  (s32.store (i32.const 104) (get_local $scratch))
	  ;; x[12] = XOR(x[12],ROTATE(PLUS(x[15],x[14]), 7));
          (set_local $scratch (s32.add (s32.load (i32.const 124)) (s32.load (i32.const 120))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 7)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 112)) (get_local $scratch)))
	  (s32.store (i32.const 112) (get_local $scratch))
	  ;; x[13] = XOR(x[13],ROTATE(PLUS(x[12],x[15]), 9));
          (set_local $scratch (s32.add (s32.load (i32.const 112)) (s32.load (i32.const 124))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 9)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 116)) (get_local $scratch)))
	  (s32.store (i32.const 116) (get_local $scratch))
	  ;; x[14] = XOR(x[14],ROTATE(PLUS(x[13],x[12]),13));
          (set_local $scratch (s32.add (s32.load (i32.const 116)) (s32.load (i32.const 112))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 13)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 120)) (get_local $scratch)))
	  (s32.store (i32.const 120) (get_local $scratch))
	  ;; x[15] = XOR(x[15],ROTATE(PLUS(x[14],x[13]),18));
          (set_local $scratch (s32.add (s32.load (i32.const 120)) (s32.load (i32.const 116))))
	  (set_local $scratch (s32.rotl (get_local $scratch) (s32.const 18)))
	  (set_local $scratch (s32.xor (s32.load (i32.const 124)) (get_local $scratch)))
	  (s32.store (i32.const 124) (get_local $scratch))
	  ;; update loop counter
	  (set_local $i (i32.add (get_local $i) (i32.const 1)))
          (br 0)
	)
      )
    
    ;; further modify x by adding input vals by index
    (set_local $i (i32.const 64))
    (block
      (loop
        (br_if 1 (i32.ge_u (get_local $i) (i32.const 128)))
	  (set_local $in_index (i32.sub (get_local $i) (i32.const 64)))
	  (s32.store (get_local $i) (s32.add (s32.load (get_local $i)) (s32.load (get_local $in_index))))
	  (set_local $i (i32.add (get_local $i) (i32.const 4)))
	  (br 0)
	)
      )
    )

  ;; helper funcs for communicating w public part of alg
  (func $write_sec (param i32) (param s32)
    (s32.store (get_local 0) (get_local 1))
    )
  (func $read_sec (param i32) (result s32)
    (s32.load (get_local 0))
    )

  (export "ss20" (func $ss20))
  (export "write_sec" (func $write_sec))
  (export "read_sec" (func $read_sec))
)
